# Refactor 103F — Exact Wallet Session Final Cutover

Date created: August 26, 2026

Status: implementation plan

## Purpose

R103F completes the Wallet Session cutover started by R103E. The finished
system has one wallet-operation session model:

```text
owner proof
  -> exact active wallet authority
  -> exact active auth method
  -> WalletSessionAuthorizationV2
  -> one primary opaque operation credential
  -> identity-coupled browser record (record_version: 6)
  -> exact operation admission
```

Hosted-wallet handoff may mint a short-lived, origin-bound child credential.
The child resolves to the same exact server authorization, shares its quota,
and leaves the primary credential unchanged.

R103F retires:

- `reusable_wallet_sessions`;
- `opaque_wallet_session_tokens`;
- V1-to-V2 session projection;
- credential-bearing registration completion records;
- curve-specific V3 and split V4/V5 browser records;
- `not_v2` and every V1 admission fallback;
- V1-only status, quota, replay, revocation, and source-activity checks; and
- types, fixtures, guards, comments, and documentation that exist only for the
  retired implementation.

This document is authoritative at system boundaries. It does not freeze
call-site counts, line counts, commit structure, or historical test results.
The compiler and the closure searches enumerate concrete consumers while the
implementation is in progress. The final branch contains no temporary adapter
or compatibility path. Document and production line counts are
diagnostic only; neither is a completion criterion.

The invariants, boundary matrix, implementation phases, and closure ledger are
coordinated views in this one plan. The detailed inventory supplies task-level
status beneath those views.

### Boundary-local versions

Version labels retain their independent persistence and wire histories:

- `WalletSessionAuthorizationV2` is the server authorization record family;
- `record_version: 6` is the browser IndexedDB record;
- `WalletSessionOperationCredentialV1` is the primary opaque credential;
- `HostedWalletSessionOperationCredentialV1` is the hosted child credential;
- `PendingWalletRegistrationCommitV1` is the local registration recovery
  record;
- `WalletRegistrationSessionCommitReceiptV2` is the credential-free server
  completion record; and
- `WALLET_PROTOCOL_VERSION` versions the host-SDK/iframe message boundary.

## Scope

R103F depends on R107's opaque server-resolved session model, R103E's exact
authority and capability records, R109C/R109D's exact auth-method and linked
authority work, and R115's additive recovery authority.

R103F preserves:

- Passkey, Email OTP, WebAuthn, custody, and MPC cryptography;
- Wallet Session lifetime and budget policy;
- public signer identity, lane, material activation, and export policy;
- console/dashboard authentication as a separate JWT system;
- pre-V3 custody-envelope decoding at its existing persistence boundary;
- R115 additive recovery, including every pre-existing authority, method,
  envelope, linked device, and Wallet Session; and
- immutable applied D1 migrations and frozen Router A/B protocol vocabulary.

Recovery finalization creates a fresh recovery authority and target method. It
does not create a Wallet Session. Normal target login uses the direct exact
issuer after local recovery continuity is durable.

## Final domain model

### Exact server authorization

`WalletSessionAuthorizationV2` is the only reusable wallet-operation
authorization. Every active authorization requires:

- tenant and principal identity;
- wallet, authority, and auth-method identity;
- authority digest and revocation epoch;
- one or more exact capability subjects;
- authorization, mint, Wallet Session, and quota identity; and
- issue and expiry time.

The credential digest exists only in the server persistence aggregate:

```ts
type PersistedActiveWalletSessionAuthorizationV2 = {
  readonly kind: 'persisted_active_wallet_session_authorization_v2';
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
  readonly primaryOperationCredentialDigestB64u: DigestB64u;
  readonly retiredAtMs?: never;
};
```

The direct issuer prepares the authorization, quota, plaintext credential, and
credential digest before writing. One D1 batch or owning authority-activation
CAS commits the authorization, quota, and digest. An active row with a null
credential digest is invalid and cannot be returned as usable.

At most one non-retired authorization may exist for a fully scoped exact
`(walletId, authorityId, walletAuthMethodId)` tuple. Same-method replacement
retires the predecessor, closes its quota, retires hosted children, and inserts
the successor atomically. Sibling methods may each have an active session.

`WalletSessionMintId` identifies one issuance attempt. A fully scoped replay of
the same mint returns the committed authorization identity. Replacement uses a
fresh mint. Persisted `mint_id` and frozen `wallet_session_mint_id` wire fields
retain their current spelling.

### Credentials and replay

```ts
type WalletSessionOperationCredentialV1 = {
  readonly kind: 'opaque_wallet_session_operation_credential_v1';
  readonly token: string;
  readonly walletSessionId: WalletSessionId;
};

type HostedWalletSessionOperationCredentialV1 = {
  readonly kind: 'opaque_hosted_wallet_session_operation_credential_v1';
  readonly token: string;
  readonly walletSessionId: WalletSessionId;
};
```

Primary credentials use `wst_`; hosted children use `wsh_`. Their nominal types,
parsers, encodings, and record families are disjoint. The browser receives no
credential digest or client-authoritative admission claims.

A server replay cannot recover plaintext from a committed digest. Direct
issuance therefore returns one of these outcomes:

```ts
type DirectV2IssueResult =
  | {
      readonly kind: 'issued';
      readonly session: WalletSessionAuthorizationV2;
      readonly quota: ActiveWalletSessionQuota;
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | {
      readonly kind: 'already_committed';
      readonly walletId: WalletId;
      readonly authorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly mintId: WalletSessionMintId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly next: 'unlock_exact_method';
    };
```

`already_committed` never fabricates or rotates a credential. Exact-method
unlock creates a successor with a fresh mint and atomically retires the
unreachable committed session.

### Exact operation admission

The request boundary parses the credential family, resolves its digest, and
returns one exact context:

```ts
type ExactWalletSessionAdmission =
  | { readonly kind: 'admitted'; readonly context: ExactV2AdmissionContext }
  | { readonly kind: 'missing' }
  | { readonly kind: 'expired' }
  | { readonly kind: 'exhausted' }
  | { readonly kind: 'retired' }
  | { readonly kind: 'authority_unavailable' }
  | { readonly kind: 'method_unavailable' }
  | { readonly kind: 'capability_unavailable' };
```

Lifecycle outcomes are data. Exceptions are reserved for corrupt rows,
inconsistent columns or JSON, broken foreign-key identity, and impossible state
combinations.

A `sign` or `export_keys` capability subject names an exact
`MpcMaterialActivationRef`. Admission resolves that reference through the
authoritative signer/material repository before constructing a Router A/B
request. Legacy `OpaqueOwnerWalletSessionBinding` fields must come from that
resolver or lose their consumer. Wallet Session and authorization IDs cannot
stand in for threshold runtime identities.

For Ed25519, resolution supplies the exact threshold session, participant set,
`SigningWorker`, runtime-policy scope, export identity, and active capability.
For ECDSA, it supplies the key handle, relayer key, participant set,
runtime-policy scope, normal-signing state, and material activation. Every
resolved identity must agree with the exact authority, method, and capability
subject before admission succeeds.

### Exact browser record

The only active browser representation is `record_version: 6`. Its strict
boundary parser requires:

- wallet, authority, and auth-method identity;
- authorization, Wallet Session, and quota IDs;
- capability subjects, authority digest, and revocation epoch;
- issue and expiry time; and
- the primary operation credential.

The parser proves that the credential's Wallet Session ID equals the record's
Wallet Session ID. The existing `wallet_session_id` IndexedDB keyPath stores the
actual Wallet Session ID. `authorization_id` stores the authorization ID. Both
physical fields are checked against the parsed record.

`replaceExactActive` is the only active install operation. One IndexedDB
`readwrite` transaction retires predecessors for the exact wallet, authority,
and method tuple and inserts the successor. It preserves sibling methods and
authorities. The same scan quarantines V3/V4/V5 rows, rejects malformed V6
rows, preserves unknown future versions, and prevents a late legacy write from
aborting the exact install.

## Required invariants

1. Every registration, unlock, refresh, sync, linked-device activation, and
   post-recovery login issues directly through the exact V2 issuer.
2. Every active exact authorization commits its quota and primary credential
   digest atomically before success is visible.
3. Plaintext primary credentials exist only in issuer memory and at the
   receiving browser boundary. Durable registration records are credential-free;
   linked delivery stores only ciphertext and a digest.
4. Admission derives wallet, authority, method, capability, quota, and material
   identity from one exact authorization. Sibling credentials cannot satisfy
   another session.
5. At most one active session exists per fully scoped exact wallet/authority/
   method tuple. Multiple sibling-method sessions are valid.
6. Status, replay, source activity, quota, revocation, management, hosted
   exchange, signing, and export resolve the same exact identity.
7. Replacement and revocation retire the exact authorization, quota, and hosted
   children in the transaction that changes the owning state.
8. Expiry, exhaustion, retirement, and unavailable authority, method, or
   capability return typed outcomes rather than HTTP 500/503 failures.
   Fresh step-up remains an operation-bound authorization and never recreates a
   V1 reusable session.
9. A lost founding-registration response resumes from a durable pending local
   commit and the server's credential-free committed projection. Local
   discovery state publishes atomically before exact-method unlock.
10. Linked activation replay returns the original recipient-bound ciphertext
    and exact session. Acknowledgement cleanup remains authenticated and
    resumable after the live link session is deleted.
11. Hosted children are origin-bound, resolve one exact parent, share its quota,
    and become unavailable with the parent lifecycle.
12. Recovery remains additive. A crash after server promotion can resume local
    continuity publication without another recovery code or plaintext durable
    recovery secret.
13. Material promotion updates every affected exact server projection and
    same-authority browser record without rotating session, quota, mint, or
    credential identity.
14. Current browser readers quarantine known legacy rows and preserve unknown
    future rows. Every unsupported row reaches an explicit terminal UI state.
15. The host SDK and iframe agree on `WALLET_PROTOCOL_VERSION` before adopting
    the port or exchanging Wallet Session data.
16. Cutover parsing remains confined to the named request, IndexedDB, and D1
    persistence boundaries. The final closure search finds no V1 request or
    runtime compatibility branch.
17. Applied migrations remain byte-for-byte unchanged. The final schema has no
    V1 table, trigger, view, or alias.

## Boundary matrix

Each row is a completeness obligation and one view of this authoritative plan.
Implementation phases refer to these IDs instead of restating their designs.
Typed call sites are enumerated by narrowing or deleting the old types and APIs.
The temporary implementation appendix owns exact file/call-site lists while a
phase is active.

| ID | Boundary | Producer(s) | Consumers | Replay / recovery | Persistence and final shape | Code-cutover action | Primary proof |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | D1 authorization persistence | Direct issuer and authority-activation CAS | Admission, status, quota, replay, revocation, hosted children | Full-scope mint replay returns committed identity | V2 authorization, quota, and primary digest commit atomically | Delete V1 tables, ports, and projections in the enforcement migration and source cutover | Failure injection plus migration checks |
| B2 | Session issuance | Registration, unlock, refresh, sync, linked activation, post-recovery login | Browser installers, signing runtimes, status | `issued` / `already_committed`; unlock replaces unreachable committed session | Direct V2 response and credential digest | Convert every issuer directly; delete reusable-session issuers and response adapters | Issuance matrix and same-mint tests |
| B3 | Registration completion | Registration activation and deferred provisioning | Registration client, replay route, local discovery/install transaction | Pending local commit plus credential-free committed projection | `WalletRegistrationSessionCommitReceiptV2` only | Delete credential-bearing receipts, bearer reconstruction, and replay-adapter storage | Lost response through immediate signing |
| B4 | Operation admission | Primary and hosted credential resolvers | Both curve validators, pool fill, seal, preflight, warm recovery, step-up | Authorized-operation replay resolves the same exact context | Required V2 credential reader and typed admission union | Delete V1 credential resolution and `not_v2` from core admission | Both curves reject fallback |
| B5 | Runtime material resolution | Capability-subject material repository | Router A/B requests, signing, export, pool fill | Re-resolution uses the same activation identity | Exact `MpcMaterialActivationRef` projection | No compatibility; delete or replace every opaque-binding consumer | No synthesized runtime IDs |
| B6 | Status, quota, and source activity | Exact status and authorization stores | Browser reconciliation, quota, operation replay, lifecycle UI | Full digest-free projection repairs lost promotion response | Exact V2 scope and typed lifecycle | Reject partial legacy scope and delete V1 status/quota/source readers | Full-scope replay and lifecycle tests |
| B7 | Revocation and replacement | Method, authority, replacement, and budget CAS operations | Admission, status, hosted children, sibling sessions | Exhausted identity remains readable for typed step-up | Exact session, quota, and child lifecycle update together | Delete V1 cleanup statements after all callers use exact retirement | Transaction tests |
| B8 | Browser persistence | Registration, unlock, refresh, sync, recovery, device-link installers | Signing surface, login, readiness, step-up, management, public API | Bootstrap and exact status reconcile stale projections | One V6 record selected by exact tuple | Write V6 directly; quarantine V3/V4/V5 and delete their writers/read APIs | Mixed-version IndexedDB tests |
| B9 | Host SDK and iframe | Host CONNECT and iframe READY handshakes | Host applications, iframe router, hosted child cache | Version mismatch is terminal and retryable after matching code is loaded | Matching protocol version and exact message shapes | Change both sides in one code cutover; keep no message adapter | Both skew directions fail closed |
| B10 | Hosted handoff | Hosted issue and redemption routes | Iframe child cache and child-authorized HTTP routes | Single-use exchange; child resolves exact parent | Origin-bound `wsh_` digest record with parent FK | Delete V1 exchange shapes, curve fields, and token caches | Origin, parent lifecycle, and primary-preservation tests |
| B11 | Device-link activation | Device 2 preparation and server activation CAS | Local installer, runtime activation, acknowledgement | Activation replay returns original recipient-bound ciphertext and session | Exact session plus sealed delivery row | Convert current pending states through the exact state machine and delete V1 session delivery | Four factor paths plus loss/replay tests |
| B12 | Device-link acknowledgement | Device 2 durable intent and acknowledgement route | Delivery cleanup, allocation cleanup, link cleanup, bootstrap replay | Cleanup receipt authenticates replay after live-session deletion and completion | One idempotent acknowledgement lifecycle | Live link authenticates until deletion; retain the receipt through the bounded post-completion replay window | Crash after every transition |
| B13 | Recovery | R115 finalization and replay | Local continuity publisher, ordinary exact login | Reload resumes committed target projection without another code | Additive server projection plus non-discoverable local commit | Existing response projection remains authoritative; local pending state publishes or fails closed | Interruption after promotion for both targets |
| B14 | Material promotion | Authority-promotion CAS and exact status | Every affected server snapshot, browser sibling record, promoted runtime | Status read repairs a lost promotion response | Updated digest/subjects with stable session identities | No compatibility; runtime waits for complete reconciliation | Lost-response and sibling-method tests |
| B15 | Management and read routes | Request credential resolver | Route policy matrix consumers | Each replay retains the original exact scope and assurance | Exact admission context only in core services | Convert every route and delete the V1 request resolver | Route policy tests |
| B16 | Public/shared types | Server responses, IndexedDB parsers, iframe protocol | SDK, browser, generated bindings, tests | Boundary parsers reject removed and cross-family shapes | Exact server, credential, browser, and iframe unions | Delete temporary parsers, aliases, fixtures, and messages | Type fixtures and closure searches |

### Route policy matrix

Core route services receive only an `ExactV2AdmissionContext`. Compatibility is
normalized once at the request boundary.

| Route family | Exact identity | Capability / assurance | Quota |
| --- | --- | --- | --- |
| Session status | Credential's method and authority | Active exact session | Neutral |
| Signing and pool fill | Method, authority, and material activation | Matching `sign` subject | Consuming |
| Key export | Method, authority, and material activation | `export_keys` plus fresh step-up | Neutral |
| Device-link approval/preflight | Source method and authority | `link_devices` plus existing owner assurance | Neutral |
| Device revocation | Owner method and target authority | `revoke_devices` plus required fresh proof | Neutral |
| Email factor release | Email method and enrollment | Matching Ed25519 subject plus one-time proof | Neutral |
| NEAR funding | Method and Ed25519 activation | Matching `sign` subject | Neutral |
| Public-key/authenticator inventory | Method and authority | Existing read policy | Neutral |
| Auth identity link/unlink | Method and authority | Existing fresh-step-up policy | Neutral |
| Custody ownership upgrade | Method equals envelope owner | Existing custody proof | Neutral |
| Hosted exchange | Parent method and authority | App, wallet, and iframe origins; audience-bound child | Parent policy |

No route may infer an auth method from wallet-wide uniqueness. Device-link
approval takes its source method from the authenticated exact credential.
Scanning a QR code does not add a Device 1 method chooser.

### Untyped and persistence-visible inventories

The type system enumerates typed TypeScript consumers. These inventories remain
explicit because compilation cannot prove their closure.

#### Issuance boundaries

| Issuer boundary | Required final result |
| --- | --- |
| Founding registration activation | Direct V2 `issued` or credential-free `already_committed` |
| Deferred NEAR provisioning | Same registration receipt and response family as activation |
| Passkey unlock | Direct V2 issuance for the selected exact method |
| Email OTP unlock | Direct V2 issuance for the selected exact method |
| Wallet Session budget refresh | Same-method exact replacement with a fresh mint |
| Account sync/bootstrap | Direct V2 response normalized by the active client generation |
| ECDSA post-registration activation | Direct V2 issuance bound to exact ECDSA material |
| Linked-device activation | Direct V2 issuance plus recipient-bound sealed delivery |
| Post-recovery normal login | Direct V2 issuance after durable local continuity |

#### Persistent state and counters

| State | Cutover treatment |
| --- | --- |
| `reusable_wallet_sessions` | Drop the table, indexes, triggers, ports, and readers in the enforcement cutover |
| `opaque_wallet_session_tokens` | Drop the table and delete every bearer issuer/resolver |
| `registration_replay_opaque_wallet_session_tokens_v1` | Drop the temporary table and delete its adapter issuer/resolver/tests |
| V2 rows with null credential digest | Treat as unusable; retire before enforcement |
| All-null-scope pending operations | Reject during migration preflight or normalize to fully scoped V2 rows in code |
| V1 hosted exchanges | Delete V1 exchange tables, request shapes, and redemption code |
| V1-only quotas | Delete unreferenced rows during enforcement |
| Registration completion rows | Rewrite to credential-free receipts or delete when replay state is unnecessary |
| Linked sealed deliveries | Retain until exact acknowledgement tombstones ciphertext |
| Acknowledgement cleanup receipts | Retain through bounded replay completion/expiry |

#### Wire, dynamic dispatch, and version skew

| Surface | Inventory requirement |
| --- | --- |
| Primary and hosted credential prefixes | Separate parsers and record families; cross-prefix input rejected |
| Host CONNECT / iframe READY | Both directions carry and validate `WALLET_PROTOCOL_VERSION` |
| Iframe Wallet Session messages | Removed reusable-session fields have no runtime handler |
| Router A/B and worker messages | Dynamic discriminators and handlers are searched separately from imports |
| Route registration and assembly | Every issuing and admitting route maps to B2, B4, or B15 |
| Generated bindings | Regenerate or update exact shapes; search generated entrypoints for legacy fields |
| Shared IndexedDB | Final, malformed, legacy, and unknown-future records are exercised |

Exact file and symbol lists for these rows may live in the temporary
implementation appendix. They are regenerated from the current tree and removed
when their boundary reaches its final state.

## Critical boundary designs

### Registration receipt and persisted-credential remediation

Before the terminal registration request, the client persists one invisible
`PendingWalletRegistrationCommitV1` with ceremony and idempotency identity,
founding method, local factor binding, and sealed local signer/custody material.
It contains no Wallet Session credential and does not make the wallet
discoverable.

The server journal stores `WalletRegistrationSessionCommitReceiptV2`. The
receipt contains the operation fingerprint, committed session identities, and
the public signer, account, capability, custody-manifest, and founding-authority
projection required for local validation. It rejects generic response payloads,
primary or child credentials, credential-bearing bootstraps, and local secrets.

First execution builds the public `issued` response from ephemeral issuer
memory after the receipt CAS succeeds. Final replay returns
`already_committed` with the same credential-free projection. The client
validates that projection against its pending record, atomically publishes the
profile, authenticator, authority, method, signer/account state, and selection,
then runs exact-method unlock.

The final code has no old-client response adapter. It never reconstructs a V1
bearer, persists an adapter digest, or returns a credential-bearing replay
shape. Any temporary registration-replay adapter table, resolver, issuer, and
tests already added during implementation are deleted in the cutover.

Existing successful completion rows under the
`wallet-registration-activate:` and
`wallet-registration-near-provisioning:` prefixes are handled only by the D1
cutover migration. Known credential-bearing shapes are rewritten to the strict
credential-free receipt when their committed projection is complete; rows that
cannot support replay are deleted. Unknown shapes abort the migration fixture.
Tests prove that no completion row, receipt parser, log, or response replay
contains a primary or hosted credential.

### Device-link credential delivery and cleanup

Device 2 creates a signer-family-neutral P-256 ECDH delivery recipient during
target preparation. The verified link authenticates its public key; the private
handle remains in the target worker.

Before server activation, Device 2 writes the pending profile, authenticator,
method/factor, authority, signer-material installation state, receipt, and
selection in one IndexedDB transaction. New records use
`pending_local_install`, remain invisible to normal discovery, and replay by
receipt identity. Terminal rejection removes only records created by this link.
The existing `server_worker_activation_pending` and
`wallet_session_issuance_pending` reasons remain retryable.

The activation CAS commits the exact authorization, quota, primary credential
digest, authority/method activation, and one complete
`linked_device_wallet_session_credential_deliveries_v1` row. The delivery uses
`p256-ecdh-aes256gcm-v1`, reusing the production WebCrypto construction already
exercised by `sealEmailOtpFactorSecretForWorker` for P-256 ECDH/AES-256-GCM. It
uses the same secure
credential randomness as every direct issuer and binds canonical AAD to full tenant scope, link
session, wallet, authority, method, authorization, Wallet Session, quota,
credential digest, recipient, issue time, and expiry. The row stores ciphertext,
the binding digest, and the expected
`WalletSessionInstallationReceiptDigestV1`. That digest covers one shared
canonical logical receipt rather than IndexedDB serialization or credential
bytes. The row stores no plaintext credential.

Activation replay returns the same row and exact session. Device 2 decrypts,
validates all identities, persists the exact browser record, activates runtimes,
durably records acknowledgement intent, and then acknowledges.

Acknowledgement is one resumable lifecycle:

```text
validate exact delivery
  -> record acknowledgement and remove ciphertext
  -> remove authority allocation
  -> remove active link session
  -> mark cleanup complete
```

After active link-session deletion, a bounded cleanup receipt retains the
Device 2 binding needed to authenticate only the exact acknowledgement replay.
The route resolves that receipt before requiring a live link session. Replay
continues the first incomplete transition and never restores ciphertext. The
binding covers the Device 2 credential, link session, authority, package-set
digest, authorization, Wallet Session, credential digest, and installation-
receipt digest. A missing or conflicting receipt fails closed. The completed
receipt remains until the acknowledgement replay window elapses.

Loss of the recipient handle or delivery expiry resumes the durable local
authority installation and runs exact-method unlock. It does not reseal the
committed credential or start a second link.

### Shared IndexedDB and SDK/iframe boundaries

The final SDK consumes direct exact issuer responses and writes V6 records
immediately. No client-capability marker or capability-tagged replay receipt is
part of the final protocol.

Readers quarantine V3/V4/V5 rows observed during bootstrap or install. R103F
retains the current IndexedDB keyPath and does not bump
`SEAMS_WALLET_DB_VERSION` while its upgrade function deletes every object
store. A keyPath change requires `versionchange` and remains outside this
cutover. Unknown future rows reach `upgrade_required`; they are never reported
as `corrupt`.

Registration, unlock, sync, recovery, and link responses may retain family-
specific signer-runtime bootstrap metadata. Those bootstraps contain no Wallet
Session bearer. One exact browser record authenticates the capability subjects;
each bootstrap remains bound to its own material activation and threshold
runtime identity.

The npm host SDK and iframe change together in the code cutover. CONNECT carries
the host protocol version. The iframe validates it before adopting the port.
READY carries the iframe version, which the host validates before marking the
connection ready. Either skew direction returns
`WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` before Wallet Session data crosses the
`postMessage` boundary. On a bad CONNECT version, the iframe reports its own
version through the transferred port, closes the port, and never adopts it.
Both directions retain the stable mismatch behavior in tests; no message
adapter remains.

### Hosted child credentials

`wallet_session_hosted_credentials_v2` stores the exact parent identity, child
credential digest, application and wallet origins, expiry, and lifecycle. The
exchange code is single-use. Child expiry never exceeds parent expiry.

Issue requires the actual request `Origin` to equal `appOrigin`. The requested
`walletOrigin` must equal authenticated tenant wallet-origin metadata or an
explicit server-side allowlist entry. Redemption and child-authorized HTTP calls
require the actual request `Origin` to equal the stored `walletOrigin`. The
iframe accepts the child only when its adopted parent `MessageEvent.origin`
equals the stored `appOrigin`.

Parent replacement, explicit retirement, method revocation, and authority
revocation retire children in the owning transaction. Parent expiry makes them
logically unavailable. Resolution returns the parent's
`ExactV2AdmissionContext` and creates no second quota.

### Recovery and material promotion continuity

R115 recovery remains additive. Both finalization response branches return a
strict server-read projection containing the active recovery authority and
target method. Boundary parsers validate wallet, authority, method, target,
digest, and lifecycle relationships. Google/Email enrollment validation remains
inside the atomic server commit.

After server promotion, a resumable non-discoverable local commit must survive
reload while authority, method, selection, profile, authenticator, account, and
signer continuity become durable. It stores no recovery code, factor secret,
custody seed, or signer root in plaintext. `ready_for_sign_in` is returned only
after every fail-closed login prerequisite is durable. Ordinary unlock accepts
the exact installed recovery authority and method; only `device_link`
provenance enters linked unlock.

Material promotion updates the authority and every affected non-retired V2
snapshot in one CAS. Authority digest and capability subjects change;
authorization, Wallet Session, quota, mint, credential, issue time, and expiry
remain stable. The response or authenticated exact status read returns every
same-authority projection needed to reconcile browser records before the
promoted runtime becomes active. Unprovable continuity retires the affected
sessions and requires exact-method unlock.

## Detailed implementation inventory

This checklist records concrete remaining work. Items stay unchecked until the
named production path is replaced and any obsolete implementation is deleted.
When compilation cannot enumerate a consumer, the item also names the search or
runtime surface that proves closure. Detailed tasks reference the boundary IDs
above and remain part of this authoritative plan.

When implementation discovers another edge, add it once: update the boundary
row if producer/consumer, persistence, replay, compatibility, or deletion
ownership changes; otherwise add one task under the owning inventory section.
Phase summaries and completion criteria reference that source instead of
copying it.

### Active implementation seams

The largest affected files remain explicit because they define review and
extraction seams:

- `packages/wallet/src/SeamsWeb/operations/auth/login.ts`;
- `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`;
- `packages/wallet/src/core/indexedDB/seamsWalletDB/repositories.ts`;
- `packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationService.ts`;
- `packages/wallet/src/SeamsWeb/operations/registration/registration.ts`;
- `packages/wallet/src/core/rpcClients/relayer/walletRegistration.ts`;
- `packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts`;
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`;
  and
- `packages/wallet/src/SeamsWeb/operations/recovery/walletRecovery.ts`.

Required shaping work:

- [ ] Move pending registration construction, committed-projection parsing,
      local promotion, and exact session persistence behind one client terminal-
      commit seam; keep public orchestration entrypoints in `registration.ts`.
- [x] Isolate the direct server issuer and credential-free receipt from
      `d1WalletRegistrationService.ts`.
- [x] Isolate the terminal registration response parser from
      `walletRegistration.ts`.
- [ ] Extract linked local-install and acknowledgement state-machine code when
      I6 changes those paths.
- [x] Extract exact-session reader logic from `login.ts` and
      `BrowserSigningSurface.ts` as I8 converts their callers.
- [x] Regenerate the exact `readActiveForWallet` consumer inventory before I8.
      The current tree has 40 executable uses across 18 production consumer
      files: 37 direct reads and three bound ports. The generated current list
      below controls the conversion work.
- [x] Record the final V2 issue, persistence, read, admission, retirement, and
      replay APIs that remain after deletion so the closure search distinguishes
      the intended exact surface from a missed legacy replacement.

Final exact survivor API inventory:

| Responsibility | Surviving API |
|---|---|
| Direct issue | `AuthorizationService.issueDirectWalletSessionAuthorizationV2` |
| Server persistence | `D1AuthorizationStore.commitDirectWalletSessionAuthorizationV2` |
| Same-mint replay | `readWalletSessionAuthorizationV2ByMint` returning the committed exact identity without plaintext credential recovery |
| Credential admission | `readWalletSessionAuthorizationV2ByOperationCredential` and `readExactWalletSessionStatusByOperationCredential` |
| Authorized-operation admission and replay | `admitAuthorizedOperation` and `completeAuthorizedOperation` |
| Method retirement | `retireWalletSessionAuthorizationsForAuthMethod` |
| Authority retirement | `prepareRetireWalletSessionAuthorizationsV2ForAuthority` inside the owning authority CAS |
| Browser install and same-method replacement | `writeExactWithOperationCredential` through `replaceExactActive` |
| Browser exact read | `readExactWithOperationCredential` and `readExactActiveForWallet` |
| Browser lock retirement | `retireExactActiveForWallet` |

Behavior-neutral extraction, legacy deletion, and behavior changes should use
coherent commits where practical. An extraction that touches more than five
existing files, creates a forwarding compatibility wrapper, widens a domain
input, or invents a new layer is deferred until its operating path works.

### I1 — Server V1 persistence and service surface (B1, B6, B7)

- [x] Delete `readReusableWalletSessionStatus` from
      `d1AuthorizationStore.ts`, `authorization/service.ts`, and
      `authServicePort.ts`.
- [x] Delete `putWalletSessionAuthorization` and its V1 readback helpers.
- [x] Delete `issueReusableWalletSession` and its preparation/domain inputs.
- [x] Delete the V1 `readWalletSessionAuthorizationByMint`; narrow the V2
      reader around full scope, exact method, and `WalletSessionMintId`.
- [x] Delete `revokeReusableWalletSessionsForAuthMethod` and its prepared SQL
      statement builder; exact auth-method retirement now targets V2
      authorizations directly.
- [x] Delete `putOpaqueWalletSessionToken`.
- [x] Delete `readOpaqueWalletSessionToken`.
- [x] Delete `readOpaqueWalletSessionTokenByIdentity`.
- [x] Delete `issueOpaqueWalletSessionToken` and
      `resolveOpaqueWalletSessionToken` from the service and route port.
- [x] Delete `ResolvedOpaqueWalletSessionToken`, legacy curve-binding types,
      and pre-provenance runtime branches that depend on those APIs.

I1 closure evidence (2026-08-30): exact-name searches across `packages`,
`apps`, and `tests` found no named V1 persistence/service symbols,
`ResolvedOpaqueWalletSessionToken`, curve-binding types, parser/runtime branches,
or the stale `WalletSessionAuthorization` builder. The direct V2 issuer and
exact V2 readers remain reachable from the registration, unlock, sync, hosted,
status, device-link, and operation routes; the wallet-server type-check and
focused authorization tests (19/19) pass.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`
- `packages/wallet-server/src/authorization/service.ts`
- `packages/wallet-server/src/router/framework/authServicePort.ts`
- `packages/wallet-server/src/authorization/domain.ts`

### I2 — Direct V2 issuance, registration replay, and promotion (B1, B2, B3, B14)

- [x] Delete `issueWalletSessionAuthorizationV2FromReusableSession`.
- [x] Delete `refreshWalletSessionAuthorizationV2FromReusableSession`.
- [x] Delete `projectReusableWalletSessionV2` and its projection types.
- [x] Replace separate session and credential writers with one issuer that
      prepares `{ session, quota, primaryCredential, credentialDigest }`.
- [x] Delete `putWalletSessionAuthorizationV2OperationCredential` and
      `issueWalletSessionAuthorizationV2OperationCredential`; no production API
      may update `operation_credential_hash` after session insertion.
- [x] Persist the session, quota, and primary digest in one batch or owning
      authority-activation CAS before returning success.
- [x] Rebuild V2 in the enforcement migration so an active row requires a
      non-null primary digest.
- [x] Make same-method replacement retire its predecessor session and close its
      quota in the successor transaction without mutating same-mint replay.
- [x] Retire hosted children in the same successor transaction.
- [x] Add the full-scope exact-tuple partial unique index after deterministic
      duplicate preflight.
- [x] Preserve historical `mint_id` uniqueness; every replacement receives a
      fresh mint and policy-derived mint helpers are deleted.
- [x] Make the V2-by-mint reader accept the narrow replay key and return the
      committed exact identity without reconstructing the expected record.
- [x] Implement `issued` and `already_committed` without credential rotation or
      fabrication.
- [x] Persist `PendingWalletRegistrationCommitV1` before the terminal request
      and keep it invisible to normal discovery.
- [x] Make the pending record sufficient for Passkey and Email OTP Ed25519
      reload by retaining the exact publication facts and validating them
      against the credential-free committed projection before publication.
- [x] Keep ECDSA-only and mixed pending records durable after terminal replay,
      and return a typed `unlock_required` continuation bound to the exact
      wallet, ceremony, key families, activation journal, authority, and
      method instead of attempting publication without custody material.
- [ ] Retain recoverable ECDSA local-finalization state in the pending record
      and validate it against the committed projection before publication.
- [x] Change final registration replay to credential-free committed projection
      plus `unlock_exact_method`.
- [x] Validate Passkey Ed25519 deferred-NEAR replay against the pending record
      and atomically publish profile, authenticator, authority, method,
      signer/account state, selection, and an issued V6 Wallet Session.
- [x] Extend reload replay and atomic publication to Email OTP registration.
- [ ] Extend reload replay and atomic publication to ECDSA-only or mixed
      registration finalization.
- [x] Implement the nine-store publication primitive: re-read the exact pending
      row in-transaction, validate Passkey/Email OTP and founding identities,
      roll back all local state on failure, and retain mixed activation pending
      state until deferred NEAR publication.
- [x] Convert the Passkey Ed25519-only deferred-NEAR registration caller to the
      publication primitive, including custody material, and prove a late
      key-material failure exposes no partial wallet before a successful retry.
- [x] Convert the Email OTP Ed25519-only deferred-NEAR registration caller to
      the same publication primitive, including custody material, and prove the
      same rollback-and-retry behavior through the production batch builder.
- [x] Replace activation and deferred-provisioning completion rows with
      `WalletRegistrationSessionCommitReceiptV2`.
- [x] Use one credential-free committed installation projection for terminal
      replay.
- [x] Consume the credential-free projection for Passkey Ed25519 deferred-NEAR
      recovery. Retain the pending row until exact-method unlock installs V6,
      then let idempotent replay remove the completed journal.
- [x] Consume that projection for Email OTP pending-commit recovery, validating
      the receipt, founding authority/method identities, and provisioning plan
      before atomic local publication.
- [ ] Consume that projection for ECDSA-only and mixed pending-commit recovery,
      validating the receipt, prepared fingerprint, authority set,
      provisioning plan, and already-finalized ECDSA state before local
      publication.
- [x] Delete the old-client replay adapter, its V1 bearer reconstruction, and
      every adapter-only resolver and test.
- [x] Drop `registration_replay_opaque_wallet_session_tokens_v1` in migration
      `0031_r103f_delete_registration_replay_tokens.sql` and delete its
      service/store surface.
- [x] Update Route 3 comments and tests from byte-identical bearer output to
      stable fingerprint and committed-projection identity.
- [x] Make the receipt parser reject bearer fields, credential-bearing
      bootstraps, local secrets, and generic persisted response payloads.
- [x] Delete known credential-bearing historical registration completions,
      preserve credential-free claims and V2 receipts, and abort on unknown
      registration journal shapes for both known prefixes.
- [x] Update material promotion so the authority CAS refreshes every affected
      non-retired V2 snapshot while preserving session identity.
- [x] Extend authenticated exact status to return the complete digest-free
      projection used for promotion-response loss and bootstrap reconciliation.

Convert every current issuer:

- [x] founding registration in `d1WalletRegistrationService.ts`;
- [x] registration session replay/reuse in `d1WalletRegistrationService.ts`;
- [x] Wallet Session budget refresh in `d1WalletRegistrationService.ts`;
- [x] linked Ed25519 activation in `d1WalletRegistrationService.ts`;
- [x] active unlock in `d1RouterApiAuthService.ts`, including exact request
      identity parsing, credential-free same-mint replay, and exact committed
      identity and credential-digest validation without credential rotation;
- [x] sync bootstrap in `syncAccountBootstrap.ts`, including mixed-wallet
      ECDSA activation through the same primary V2 credential; this item cannot
      close while `thresholdEcdsa.ts` resolves that credential only through the
      V1 opaque-token store or `syncAccount.ts` installs a late curve-specific
      browser row;
- [x] Bind sync recovery from `already_committed` to the same committed wallet,
      auth method, and selected credential, allow exactly one fresh challenge,
      and fail closed if the replacement terminal repeats or changes identity;
- [x] ECDSA post-registration activation in `thresholdEcdsa.ts`: direct-capable
      requests now issue the exact V2 session and primary operation credential
      atomically, validate same-mint replay and resolved ECDSA material before
      persistence, and persist only the exact browser record.
      `tests/unit/routerAbEcdsaExactActivationWire.unit.test.ts` rejects the
      retired bearer response and material drift;
- [x] Delete `mintRouterAbEd25519YaoWalletSessionV1`; its sync and registration
      callers use the exact Ed25519 session projector;
- [x] Delete `issueRouterAbEd25519OpaqueWalletSessionToken` and every direct
      caller; and
- [x] Recovery finalization remains credential-free and recovered authorities
      receive sessions only through normal exact-method direct-V2 unlock;
      device-link activation persists its exact primary credential digest in
      the owning authority-activation CAS. Final issuer searches find no V1
      recovery or device-link issuer.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationService.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration.ts`
- `packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary.ts`
- `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService.ts`
- `packages/wallet-server/src/router/cloudflare/d1/registration/walletRegistrationEstablishedSessionIssuer.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/syncAccountBootstrap.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- `packages/wallet-server/src/core/threeRouteRegistrationContracts.ts`
- `packages/shared-ts/src/utils/registrationEstablishedSession.ts`

Remaining issuer symbols include `RegistrationEstablishedSessionIssuerAuthorizationService`,
`issueSyncAccountBootstrapV1`, `handleStrictEcdsaSessionActivation`, the
budget-refresh and linked-activation `issue_wallet_session_v1` branches, and
`mintRouterAbEd25519YaoWalletSessionV1`. The legacy registration grant issuer
and both credential-bearing registration replay functions are deleted.

### I3 — Exact operation admission and runtime binding (B4, B5)

- [x] Make `readWalletSessionAuthorizationV2ByOperationCredential` required in
      `authServicePort.ts`; the production assembly and every exact admission
      consumer now call one non-optional port.
- [x] Delete `WalletSessionOperationCredentialResolution.kind === 'not_v2'`;
      an absent exact digest returns `not_found`. Remaining request-boundary V1
      resolvers are tracked explicitly for deletion below.
- [x] Delete `resolveOpaqueOwnerWalletSessionAdmission` and its request-boundary
      callers; linked add-auth-method admission now uses the exact V2
      `link_devices` administration path.
- [x] Delete the Ed25519 validator's V1-token fallback. Exact absence returns
      `wallet_session_invalid` without probing the V1 resolver.
- [x] Delete the ECDSA validator's V1-token fallback. Exact absence returns
      `wallet_session_invalid` without probing the V1 resolver.
- [x] Make operation kind required for reusable-operation admission. Every
      production caller supplies a family-specific operation kind and the
      optional overload was deleted.
- [x] Delete the `operationKind === null` ECDSA branch. Strict
      post-registration signing now requires the exact
      `evm.sign_transaction` credential, while export requires the exact
      `evm.export_key` operation step-up; the opaque-session fallback is gone.
- [x] Convert operation step-up identity resolution in
      `routerAbPrivateSigningWorker.ts`. Step-up now admits only the exact V2
      credential for the requested key family and operation kind, binds the
      request to authoritative active material, and sends the owning exact auth
      method to the execution lane. Cross-family and opaque-token fallback were
      deleted; verified owner proof retains its explicit authority-ref branch.
- [x] Convert signing-session seal authorization in `createFetchRouter.ts`.
      Seal removal now accepts only an exact signing operation credential,
      resolves the admitted family's active material, derives the authoritative
      threshold-session identity, and never probes the opaque-token store.
- [x] Convert Ed25519 reuse of an ECDSA session in `thresholdEd25519.ts`.
      Reuse now requires the exact ECDSA signing credential, the owning active
      Passkey method, matching runtime policy, and authoritative active ECDSA
      material; exact absence never probes the opaque-token store.
- [x] Convert ECDSA pool-fill admission in `thresholdEcdsa.ts`. Pool fill now
      requires the exact ECDSA operation credential and resolves every runtime
      binding from the credential's active authority material; the parallel
      opaque-binding branch was deleted, and the downstream presign runtime no
      longer derives its input type from `OpaqueOwnerWalletSessionBinding`.
- [x] Convert recovery warm-session authorization in
      `routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`. Bootstrap now
      requires the exact Ed25519 signing credential, resolves its active
      material, validates the authoritative signer, activation, threshold
      session, worker, and participants, and never probes the opaque-token
      store.
- [x] Delete the opaque-bearer override from prepared recovery admission and
      receipt-backed execute/activate. A retired `wst_` bearer cannot bypass
      the durable challenge or change the protocol-receipt authorization path.
- [x] Resolve the capability subject's exact material activation before either
      curve constructs a Router A/B request.
- [x] Assign every `OpaqueOwnerWalletSessionBinding` field to the authoritative
      material resolver or delete its consumer, including
      `thresholdSessionId`, `participantIds`, `keyManifestDigestB64u`,
      `relayerKeyId`, `runtimePolicyScope`, `keyHandle`, and
      `authorizationSessionId`.
- [x] Reject any path that substitutes a Wallet Session or authorization ID for
      a threshold runtime identity.

Primary files:

- `packages/wallet-server/src/router/auth/commonRouterUtils.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- `packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts`
- `packages/wallet-server/src/router/transport/fetch/createFetchRouter.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization.ts`
- `packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`

Live admission symbols include `WalletSessionOperationCredentialResolution`,
`resolveWalletSessionOperationCredentialAdmission`,
`WalletSessionAdministrationResolution`,
`resolveWalletSessionAdministrationAdmission`, `validateOwnerWalletSessionV1`,
and `authorizeSigningSessionSealWithExactWalletSession`.

### I4 — Status, replay, quota, and source activity (B6)

- [x] Make `/wallet/session/status` resolve only exact operation credentials in
      the final worker. Exact absence returns `invalid`, tuple mismatch fails
      closed, and neither curve-token probing nor V1 status lookup remains.
- [x] Return the complete digest-free authorization and quota lifecycle from
      the active status branch. Every branch that observed a stored
      authorization publishes `ActiveWalletSessionV1` plus the quota
      projection; the credential digest stays in persistence.
- [x] Validate immutable authorization, Wallet Session, quota, authority, and
      method identities against the credential-bound request. Persistence
      validates the authorization against its own authority, method, quota, and
      capability rows; the route validates tenant and the requested
      Wallet Session/quota tuple against the credential-resolved projection.
- [x] Reconcile stale browser records during bootstrap and after lost promotion
      responses before publishing the promoted runtime.
- [x] Return typed missing, expired, exhausted, retired, authority-unavailable,
      method-unavailable, and capability-unavailable results from persistence.
      `readExactWalletSessionStatusByOperationCredential` returns
      `ExactWalletSessionStatusV2`; exceptions remain reserved for corrupt rows,
      disagreeing columns, and broken foreign-key identity.
- [x] Convert fully scoped `isAuthorizedOperationSourceActive` rows to V2 exact
      lookup.
- [x] Delete the all-null-scope V1 source-activity branch and reject partial or
      unscoped pending rows.
- [x] Replace quota lookup through `reusable_wallet_sessions` with the V2
      authorization's `quota_id`.
- [x] Populate `linked_scope_org_id`, `linked_scope_project_id`, and
      `linked_scope_env_id` on every new grant and reject partial scope.
- [x] Replace the additive bridge trigger with an exact-only enforcement
      trigger requiring complete V2 scope.
- [x] Require authorized-operation replay to resolve the exact authorization
      that admitted first execution and reject scope, method, authority, quota,
      capability, or material disagreement.
- [x] Remove the V1 status call from Ed25519 reuse; the exact credential read's
      active quota projection supplies expiry and remaining uses.
- [x] Remove the V1 status call from ECDSA activation.

Primary files:

- `packages/wallet-server/src/router/transport/fetch/routes/sessions.ts`
- `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- a new forward signer-D1 migration; applied `0001_signer_d1_initial.sql`
  remains unchanged.

Live status/source symbols include `readAndValidateWalletSessionStatusAuthorization`,
`handleReusableWalletSessionStatus`, `readReusableWalletSessionStatus`, and
`isAuthorizedOperationSourceActive`.

### I5 — Revocation, recovery, and custody (B7, B13)

- [x] Retire V2 authorizations by exact auth-method ID during method revocation;
      `tests/unit/r109cSiblingRevocation.unit.test.ts` proves quota exhaustion,
      same-authority sibling preservation, and repeat safety.
- [x] Retire V2 authorizations by exact authority during linked-device
      revocation; the authority CAS now waits for the final active sibling,
      exhausts every owned quota, retires every owned exact session, and
      preserves unrelated authorities. `tests/unit/d1WalletAuthorityStore.unit.test.ts`
      proves the fence and isolation.
- [x] Retire hosted children in the same owning auth-method, authority, or
      same-method successor CAS.
- [x] Transition a consumed quota to exhausted through V2 while retaining exact
      identity for typed status and step-up.
- [x] Delete the unused `hasActiveWalletSessionsForAuthMethod`; its only
      implementation queried `reusable_wallet_sessions`, and no production or
      test caller required a V2 replacement.
- [x] Delete duplicate V1 revocation statement builders in
      `d1WalletAuthMethodStore.ts`.
- [x] Keep recovery finalization and committed replay credential-free, then
      issue the normal-login Wallet Session through direct exact V2 unlock for
      recovered Passkey and Email OTP authorities while preserving every
      pre-existing access path.
- [x] Preserve strict server-read recovery projections for active recovery
      authority and target method on both target branches. Credential-free
      replay accepts only the consumed recovery set and its matching retained
      locator tombstone; active or mismatched locators fail closed.
- [x] Validate wallet, authority, method, target, digest, enrollment, and
      lifecycle relationships at the response boundary.
- [x] Preserve provenance dispatch: `wallet_registration` and
      `wallet_recovery` use ordinary exact unlock; only `device_link` uses
      linked unlock.
- [x] Make recovered Email OTP unlock require the exact locally installed active
      authority and method; fail closed on absence or mismatch.
- [ ] Add a resumable local recovery commit that survives interruption after
      server promotion without persisting recovery code, factor secret, custody
      seed, or signer root in plaintext.
- [ ] Replace the in-memory-only `promoted_pending_continuity` gap with that
      durable commit before converting recovery consumers.
- [ ] Publish recovery authority, method, selection, profile, authenticator,
      account, and signer continuity atomically before `ready_for_sign_in`.
- [ ] Make replay read the same additive server commit and resume local
      installation without another recovery code.
- [x] Keep wallet lock local to browser record/runtime disposal; remote
      retirement follows explicit server lifecycle transitions.

Primary files:

- `packages/wallet-server/src/core/d1WalletAuthMethodStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody.ts`
- `packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization.ts`
- `packages/wallet-server/src/core/deviceLinking/linkedDeviceManagement.ts`
- `packages/wallet/src/SeamsWeb/operations/recovery/walletRecovery.ts`
- `packages/wallet/src/SeamsWeb/operations/authMethods/passkey/localPasskeyProjection.ts`
- `packages/wallet/src/core/rpcClients/relayer/walletRecoveryFinalize.ts`

### I6 — Device-link source, activation, and acknowledgement (B11, B12)

- [x] Delete the opaque-token fallback from
      `d1LinkedDeviceVerifiedLinkSourceReader.ts`; a missing exact identity now
      fails before method, authority, or signer material is exposed.
- [x] Require the exact V2 source session for owner approval; claim, approval,
      and metadata authentication now reject a missing exact operation digest
      without reconstructing a founding V1 curve session.
- [x] Require the exact operation credential in execution-lane preflight;
      Ed25519 and ECDSA preflight supply their concrete signing operation and
      resolve the exact session's auth-method identity before lane projection.
      The parallel opaque-owner projection branches are deleted.
- [x] Add the P-256 ECDH delivery recipient to target preparation and bind it to
      the verified link.
- [x] Persist Device 2 profile, authenticator, method/factor, authority,
      signer-material state, receipt, and selection as one invisible
      `pending_local_install` transaction before activation.
- [x] Make local pending replay idempotent by receipt identity and terminal
      cleanup preserve any pre-existing record.
- [x] Preserve `server_worker_activation_pending` and
      `wallet_session_issuance_pending` as retryable states that allocate no
      second authority.
- [x] Make resume finalize a locally pending method as active before credential
      decrypt.
- [x] Commit authorization, quota, credential digest, authority/method
      activation, and one complete sealed-delivery row in the activation CAS.
- [x] Add exact composite foreign keys to the linked installation and V2
      authorization plus unique full-scope link and digest identities.
- [x] Bind canonical AAD to tenant scope, link, wallet, authority, method,
      authorization, Wallet Session, quota, credential digest, recipient, issue
      time, and expiry.
- [x] Define the installation-receipt digest over one canonical logical shape,
      excluding IndexedDB bytes and plaintext credential bytes.
- [x] Make activation replay return the original sealed delivery, recipient,
      digest, and exact session without minting or overwriting.
- [x] Order Device 2 as durable invisible prerequisites, server activation,
      local login-prerequisite publication, credential decrypt and exact
      validation, atomic V6/selection finalization, runtime activation,
      acknowledgement-intent persistence, and acknowledgement. This leaves a
      normal exact-method unlock recovery path if the recipient handle is lost
      after the local method becomes active.
- [x] Extend acknowledgement with authorization ID, Wallet Session ID,
      credential digest, and installation-receipt digest.
- [x] Reject cross-session or stale acknowledgement before consuming delivery.
- [x] Implement one idempotent acknowledgement lifecycle covering delivery
      tombstone, ciphertext removal, allocation deletion, link-session deletion,
      and completion.
- [x] Delete or fold any parallel sealed-delivery cleanup that could race the
      acknowledgement lifecycle.
- [x] Retain a bounded Device 2 authentication binding in the cleanup receipt;
      bind Device 2 credential, link session, authority, package set,
      authorization, Wallet Session, credential digest, and receipt digest, and
      resolve it before requiring a live link session.
- [x] Persist pending acknowledgement intent locally and provide an idempotent
      replay helper that clears the intent together with the local
      delivery-resume record after cleanup completes.
- [x] Invoke pending acknowledgement replay from the production bootstrap path.
      The wallet host reads the exact persisted V6 tuple, retries through the
      Wallet Session bearer-only acknowledgement transport, and leaves the
      durable intent untouched while the exact session is unavailable.
- [ ] Recover recipient-handle loss or delivery expiry through durable local
      install plus exact-method unlock, without resealing or relinking.
- [ ] Preserve interactive cancellation across `claimed`,
      `awaiting_target_factor`, `awaiting_source_contribution`, and
      `provisioning`. Device 1 retains its owner-authenticated cancellation
      identity and targets the authenticated current revision, Device 2 emits
      one terminal `cancelled`, and the hosted menu reaches an explicit retry
      state with opener focus restored. Postcommit local installation and
      active sessions remain outside that route.
- [x] Delete `INSTALLATION_SCHEMA_SQL` and other runtime `CREATE TABLE` strings from
      `d1LinkedDeviceAuthorityInstallService.ts`; the service now contains only
      operational DML for migration-owned tables.
- [x] Move `linked_device_authority_allocations` to the additive migration while
      preserving immutable `0018` ownership of
      `linked_device_authority_installations` and its
      `target_factor_verified_at_ms >= 0` constraint.
- [x] Verify the linked Passkey exact method exposes account-menu inventory and
      NEAR plus EVM-family signing-ready state immediately after linking.
- [ ] Verify export and the remaining factor combinations immediately after
      linking without a lock/unlock cycle.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceVerifiedLinkSourceReader.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/walletExecutionLanePreflight.ts`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceAuthorityInstallService.ts`
- `packages/wallet-server/src/router/domains/emailOtp/emailOtpRouteHandlers.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingAuthorityInstallation.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingHttpTransport.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/deviceLinkingPorts.ts`
- `packages/wallet/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/host/auth-menu/session.ts`

### I7 — Hosted and management request boundaries (B10, B15)

- [x] Back hosted issue and redemption with an origin-bound V2 child credential
      that resolves one parent, shares its quota, and preserves the primary.
- [x] Give primary and child credentials separate nominal types, `wst_`/`wsh_`
      encodings, parsers, tables, and lookup branches.
- [x] Make hosted issue accept `{ appOrigin, walletOrigin }`, redemption accept
      `{ exchangeCode, nonce, appOrigin, walletOrigin }`, and success return the
      parent Wallet Session ID, one hosted child credential, and its expiry.
- [x] Remove `curve` and `walletSessionToken` from exact hosted wire shapes.
- [x] Require issue request Origin to equal `appOrigin`.
- [x] Require requested `walletOrigin` to equal authenticated tenant wallet-origin
      metadata or a server allowlist entry.
- [x] Require redemption and child-authorized HTTP Origin to equal stored
      `walletOrigin`, and all supplied origins to equal the exchange row.
- [x] Cache a hosted child in the iframe only when adopted parent origin equals
      stored `appOrigin`.
- [x] Add the parent composite foreign key and unique child digest.
- [x] Retire hosted children during parent replacement, explicit retirement,
      method revocation, and authority revocation; enforce parent expiry during
      resolution.
- [x] Convert the iframe hosted-session cache from per-curve token maps to one
      audience-bound child credential.
- [x] Convert Email factor-release `wallet_session` admission. The route admits
      one exact active Email OTP method whose normalized email hash matches the
      active enrollment and whose authorization carries an Ed25519 signing
      subject; enrollment mismatch, the wrong key family, or missing exact
      state fails before unsealing without consulting the V1 token resolver.
- [x] Convert `/auth/identities` link/unlink admission. Inventory and mutations
      derive the wallet, method, and authority from one exact credential;
      mutation step-up must prove that same method and authority, so a sibling
      same-wallet passkey fails before strong-auth or identity side effects.
- [x] Convert `/near/public-keys` admission. The route resolves the presented
      operation credential through the exact V2 authorization, derives the
      wallet from that projection, and fails closed without probing either
      legacy curve-token store.
- [x] Convert `/webauthn/authenticators` admission. The inventory route uses
      the exact credential's wallet identity, preserves its existing RP filter,
      and rejects missing exact state without legacy curve-token probes.
- [x] Convert custody-envelope ownership upgrade admission. The route checks
      the exact credential wallet against the path and forwards its required
      auth-method identity; the ownership service rejects an envelope naming a
      sibling method before any envelope-store access.
- [x] Convert registration funding/session admission. Implicit-NEAR funding
      admits one exact Ed25519 operation credential, derives the wallet and
      implicit account from its signer, and rejects missing exact state or a
      different signer without reading the V1 opaque-token store.

Primary files:

- `packages/wallet-server/src/router/transport/fetch/routes/sessions.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/auth.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/nearPublicKeys.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/webauthnAuthenticators.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody.ts`
- `packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/host/hostedWalletSeamsSession.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/router.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/shared/messages.ts`

### I8 — Exact browser persistence and consumers (B8)

- [x] Delete the V3 `WALLET_SESSION_AUTHORIZATION_RECORD_VERSION`.
- [x] Delete `ActiveWalletSessionAuthorizationProjection` and its retired V3
      sibling.
- [x] Delete `WalletSessionAuthorizationTokenBundle`.
- [x] Delete curve token/ID extractors and V3 builders, parsers, serializers,
      merges, and retirement helpers.
- [x] Delete V3 `replaceActive`, `createOrMergeExactActive`, and
      `upsertActiveWithCurveMerge` behavior.
- [x] Delete `readActiveForWallet`.
- [x] Delete `persistActiveWalletSessionAuthorizationCurve` and
      `persistActiveWalletSessionAuthorizationFromRegistration`.
- [x] Delete the V3 ECDSA bootstrap projection.
- [x] Correct the V5 boundary so its physical `wallet_session_id` is the
      operation credential's Wallet Session ID, reject key/credential drift,
      and preserve same-wallet sibling methods during exact replacement.
- [x] Make the existing V3 and V5 writer boundaries preserve unknown future
      record versions; exact replacement also contains valid late legacy rows
      while continuing to reject malformed known rows.
- [x] Make the existing V5 operation-credential reader and its current browser
      signing, login, and ECDSA-runtime consumers surface a matching unknown
      future row as `upgrade_required`; a matching future row dominates V5,
      while an unrelated sibling method remains readable and malformed known
      V5 remains fail closed.
- [x] Define one branch-specific V6 builder and one strict parser requiring
      exact identities, subjects, lifecycle, and primary credential.
- [x] Reject session/credential mismatch at parsing and before IndexedDB write.
- [x] Preserve `wallet_session_id` as the Wallet Session keyPath, store
      `authorization_id` separately, and cross-check both.
- [x] Make exact `replaceExactActive` the only active install API with
      same-method retirement and sibling preservation in one transaction.
- [x] Quarantine known V3/V4/V5 rows, reject malformed V6, preserve unknown
      future rows, and contain late legacy writes in every reader/install.
- [x] Remove only obsolete Wallet Session rows; preserve every unrelated wallet,
      authority, method, signer-material, export-root, and recovery-code store.
- [x] Delete `walletSessionClientCapability`, its response-family tags,
      request parsers, persistence columns, fixtures, and migration-era code.
- [x] Retain the existing DB version and keyPath while the general upgrade
      function remains destructive.

Convert every reader or legacy writer:

- [x] `BrowserSigningSurface.ts`;
- [x] Make `BrowserSigningSurface.readReusableWalletSessionState` and
      `getWalletSession` project the selected exact V6 authority/method session,
      authenticate status with its operation credential, and reject legacy or
      mismatched status identity. The isolated Email OTP-to-Passkey intended
      contract proves the registration result remains immediately usable;
- [x] `login.ts`;
- [x] registration legacy persistence in `registration.ts`;
- [x] recovery/sync legacy persistence in `syncAccount.ts`;
- [x] `SigningSessionCoordinator.ts`;
- [x] `PasskeyMpcSessionManager.ts`;
- [x] `session/availability/readiness.ts`;
- [x] Canonical Wallet Session status: resolve the unlocked selected
      authority/method, read its exact V6 record, authenticate status with the
      stored operation credential, and reject mismatched session/quota identity;
- [x] Owner-lane scope resolution: require the unlocked selected
      wallet/authority/auth-method tuple, validate its exact active V6 record,
      and fail closed for missing selection, identity drift, expiry, corruption,
      persistence failure, or a future record version. The former wallet-wide
      registration/recovery and missing-selection fallbacks are deleted;
- [x] NEAR operation step-up in `BrowserSigningSurface.ts`: bind the Passkey or
      Email OTP proof to the unlocked selected method, validate its exact
      Ed25519 signing subject and material activation, and use only the exact
      operation credential. The wallet-wide Passkey and Email OTP fallbacks are
      deleted;
- [x] `clientSessionPersistence.ts`;
- [x] `ecdsaLoginPrefill.ts`;
- [x] `routerAbEd25519WalletSessionState.ts`;
- [x] `signingFlowRuntime.ts`: operation step-up resolves the unlocked selected
      authority and method, requires the exact ECDSA capability subject and
      material activation, and sends only its operation credential;
- [x] `emailOtpSigningSession.ts`: sealed-runtime signing-session authority
      resolution now validates the selected Email OTP method, active authority,
      exact ECDSA session, and material activation;
- [x] `emailOtp/ecdsaLogin.ts`: unlock/recovery publication now obtains its
      session authority from the selected exact tuple and rejects wallet-wide
      or mismatched authorization state;
- [x] `browserSigningSurfaceAssembly.ts`;
- [x] `createBrowserRecoveryPublicDeps.ts`;
- [x] `stepUpRuntime.ts`;
- [x] `ed25519YaoWarmRecovery.ts`: Passkey warm recovery requires the unlocked
      selected method, exact V6 operation credential, matching Ed25519 subject,
      authority digest and epoch, material activation, and sealed threshold
      session identity before requesting a bootstrap;
- [x] `addAuthMethodSourceClaim.ts`: resolve the unlocked selected
      authority/method tuple, validate its active exact record, and use the
      credential-bound Wallet Session identity in the source claim;
- [x] `walletHostOwnerAuthority.ts`: inject the selected-authority resolver and
      use the selected exact record and operation credential for owner approval
      and management requests; and
- [x] `publicApi/near.ts`: require the selected exact record, an Ed25519 signing
      subject, and its operation credential for implicit-account funding.

Each consumer must use an authenticated exact tuple, the current validated
method selection, a credential-bound session identity, or an intentional
multi-record result. Signing, export, funding, refresh, and management functions
cannot accept wallet identity alone.

Remove exact-first/V1 fallback from:

- [x] `login.ts`;
- [x] `walletIframe/shared/exactSessionState.ts`;
- [x] wallet iframe host auth handlers;
- [x] wallet iframe client router handlers; and
- [x] `BrowserSigningSurface.ts` lock/retirement cleanup.
- [x] Server operation admission: use only
      `wallet_session_operation_credential_v1` and delete the stale
      `reuse_wallet_session_operation_credential_v1` dispatch branch.

Primary persistence files:

- `packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.ts`
- `packages/wallet/src/core/signingEngine/session/persistence/walletSessionAuthorizationProjection.ts`

### I9 — Public types, iframe protocol, and vocabulary (B9, B16)

- [x] Delete `ReusableWalletSessionState` from the SDK domain model.
- [x] Rename `ReusableWalletSessionMintId` and parser to
      `WalletSessionMintId` and `parseWalletSessionMintId` without an alias.
- [x] Delete `ReusableWalletSessionAuthorizationId` and its compatibility
      parser; use the exact `WalletSessionAuthorizationId` identity directly.
- [x] Preserve stored `mint_id` and frozen wire `wallet_session_mint_id` names.
- [x] Delete reusable-session fields from the public `WalletSession` shape.
- [x] Delete curve-specific reusable-session signing-surface ports.
- [x] Delete legacy reusable-session iframe message fields.
- [x] Bump `WALLET_PROTOCOL_VERSION`, add the host version to CONNECT, validate
      before iframe port adoption, and retain host READY validation.
- [x] Return `WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` for either skew direction.
- [x] Change the host SDK and iframe protocol together and prove both mismatch
      directions without retaining a message adapter.
- [x] Replace `ActiveWalletSessionV1` plus separately transported credentials
      with the identity-coupled exact browser boundary type.
- [x] Delete `registration_established_wallet_session_v1`,
      `RegistrationEstablishedSessionTokens`, and `walletSessionTokenForCurve`.
- [x] Delete `ActiveWalletSession` aliases that do not denote the exact
      projection.
- [x] Delete wallet-specific JWT marker/decoder code after its last diagnostic
      caller; preserve console-session JWT types.
- [x] Preserve the frozen Router A/B `reusable_wallet_session` discriminator,
      ECDSA export-share authorization kind, and
      `consume_reusable_wallet_session` quota discriminator.

Primary files:

- `packages/wallet/src/core/types/seams.ts`
- `packages/wallet/src/SeamsWeb/signingSurface/ports.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/shared/messages.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/transport/IframeTransport.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/client/transport/iframe-transport-handshake.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/host/messaging.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/host/index.ts`
- `packages/shared-ts/src/utils/walletAuthAuthority.ts`
- `packages/shared-ts/src/utils/sessionTokens.ts`

### I10 — Documentation and source guards (B16)

- [x] Retire or replace
      `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`.
- [x] Update `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs` to
      forbid V1 tables, `not_v2`, V3 client records, and opaque fallback while
      allowing frozen reusable-operation discriminators.
- [x] Prefer the type fixtures, behavior tests, and closure searches in this
      plan over new source-text guards. R103F extended the existing focused
      suites and retired or narrowed the two pre-existing guards; it introduced
      no new source-text guard.
- [x] Update `docs/threshold-ecdsa/ecdsa-threshold-signing.md`.
- [x] Update `docs/auth-gating-routes.md`.
- [x] Update `docs/intended-behaviours.md` and registration contracts for
      credential-free lost-response replay.
- [x] Update R115 recovery contracts only where R103F changes Wallet Session
      representation. The R115 contract already states that finalization is
      credential-free and normal exact-method unlock issues the next Wallet
      Session, so no compatibility wording or representation change was needed.
- [x] Update `packages/wallet/README.md`.
- [x] Correct R103E, R107, and R109D completion records that imply the final
      cutover already landed.

## Schema migrations

Applied migrations remain immutable. Relevant historical files include:

- `packages/wallet-server/migrations/d1-signer/0001_signer_d1_initial.sql`;
- `0002_signer_post_103_canonical_upgrade.sql`;
- `0003_r107_wallet_authorization.sql`;
- `0007_r103p8_wallet_session_auth_method_provenance.sql`;
- `0015_r103e_authority_baseline.sql`;
- `0016_r103e_wallet_session_authorizations_v2.sql`;
- `0023_r109d_first_email_linked_device.sql`;
- `0024_r103f_v2_authorized_operation_claim.sql`;
- `0025_r109d_email_enrollment_wallet_cardinality.sql`;
- `0026_r115_wallet_recovery_authority_provenance.sql`;
- `0027_r115_email_otp_recovery_bootstrap.sql`;
- `0028_r103f_phase1_additive_schema_bridge.sql`;
- `0029_r103f_phase0_registration_replay_tokens.sql`; and
- `0030_r103f_wallet_session_client_capability.sql`;
- `0031_r103f_delete_registration_replay_tokens.sql`;
- `0032_r103f_exact_authorized_operation_enforcement.sql`; and
- `0033_r103f_linked_delivery_recipient.sql`.

`linked_device_wallet_session_authorizations` and
`linked_device_wallet_session_quotas` were already dropped by immutable `0015`;
R103F adds no second deletion task for them. Migration `0026` rebuilds
`wallet_authorities` and recreates the `0024` trigger, so the additive bridge
migration replaces the post-`0026` definition.

At the current checkpoint migrations through `0033` are landed. The next file
number, currently `0034` if still free, is allocated only after reconciling
landed and pending migrations from concurrent workstreams and is rechecked after
each rebase. Applied files are never renamed to resolve an allocation race.

Migrations `0029` and `0030` record temporary implementation paths that the
final cutover removes: replay-adapter storage and client-capability metadata.
They remain immutable history. The enforcement migration drops or rebuilds
their schema surfaces and may receive a non-contiguous file number.

### Temporary registration replay adapter migration

Migration `0029` added the digest-only
`registration_replay_opaque_wallet_session_tokens_v1` boundary. It remains
immutable history. Migration `0031_r103f_delete_registration_replay_tokens.sql`
drops the table, and production
TypeScript deletes every issuer, resolver, cleanup branch, and adapter-only
test.

### Additive bridge migration

The already-applied bridge migration:

- replaced the post-R115 exact-only authorized-operation trigger with a
  temporary boundary that accepts fully scoped V2 rows and all-null-scope V1
  rows while rejecting partial scope;
- adds V2 hosted child-credential and exchange tables;
- adds `linked_device_wallet_session_credential_deliveries_v1` with exact
  composite foreign keys, unique digest/link identities, recipient binding,
  ciphertext, acknowledgement, and cleanup receipt state;
- moves `linked_device_authority_allocations` to migration-owned schema after
  validating any existing runtime-created table;
- preserves valid V2 rows with non-null credential digests;
- classifies null-digest V2 rows as unusable; and
- leaves V1 tables for the enforcement migration to remove.

### Enforcement and deletion migration

This migration completes the repository cutover. It:

- rewrites or deletes known credential-bearing registration completion rows
  and aborts on unknown shapes;
- deletes V1 sessions, adapter tokens, pending V1-authorized operations, and V1
  hosted exchanges according to their named owning tables;
- retires null-digest and logically expired duplicate V2 rows;
- aborts when multiple usable credential-bearing rows remain for an exact tuple;
- rebuilds `wallet_session_authorizations_v2` with a required active credential
  digest and installs the exact-tuple partial unique index;
- replaces the parent under deferred foreign keys, preserves every hosted and
  linked-delivery child row with its exact composite reference, and aborts on
  any `PRAGMA foreign_key_check` result;
- retains completed historical operations needed for replay while requiring
  complete V2 scope for pending and new grants;
- removes V1 trigger branches, drops or rebuilds V1 child tables before their
  parent foreign keys, then removes hosted exchange storage, the adapter token
  table, ordinary opaque tokens, V1-only unreferenced quotas, and
  `reusable_wallet_sessions`; and
- leaves no V1 view or compatibility alias.

There is no V1-bearer-to-V2 backfill because plaintext credentials cannot be
recovered from their hashes and curve-scoped V1 tokens are not exact primary
credentials.

After deletion, update the required-table manifests in:

- `packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts`;
  and
- `packages/wallet-console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts`.

## Implementation phases

### Phase 0 — Secure registration persistence

- [x] Introduce `PendingWalletRegistrationCommitV1` and the credential-free
      committed installation projection.
- [x] Replace both registration completion journals with
      `WalletRegistrationSessionCommitReceiptV2`.
- [x] Update registration replay from byte-identical bearer output to stable
      fingerprint and committed-projection identity.
- [x] Delete the old-client adapter and its digest table/service surface.
- [x] Prove terminal replay and stored completion rows contain no Wallet
      Session credential (`walletRegistrationActivateRoute.unit.test.ts`
      covers both completion prefixes and exact committed-projection replay).

Exit: no code path persists or reconstructs registration Wallet Session
credentials, and a current registration path still reaches immediate signing.

### Phase 1 — Land the exact issuer and one vertical path

- [x] Apply the additive bridge migration to clean and current-history database
      fixtures.
- [x] Implement one direct issuer that atomically commits the V2 authorization,
      quota, and primary credential digest.
- [x] Narrow V2 mint replay and implement `issued` / `already_committed`.
- [ ] Convert one registration path through direct issuance, exact browser
      installation, exact admission, and immediate NEAR/EVM-family signing.
- [x] Add failure injection proving a failed batch exposes no usable session or
      quota and replay cannot rotate the credential.
- [ ] Assign every live opaque runtime-binding field to the exact material
      resolver or delete its consumer.

Exit: one complete user operating path proves the final architecture before the
remaining consumers are converted.

### Phase 2 — Convert server consumers

- [x] Convert remaining registration, unlock, refresh, sync, ECDSA activation,
      linked activation, and post-recovery login issuers. Each final producer
      either commits direct V2 atomically or remains credential-free until
      normal exact-method unlock; issuer closure searches have no V1 match.
- [x] Make the V2 credential reader required and delete `not_v2` from exact core
      admission.
- [x] Convert signing, pool fill, signing-session seal, execution-lane
      preflight, recovery warm bootstrap, and operation step-up.
- [x] Convert status, quota, source activity, authorized-operation replay, and
      typed lifecycle handling. Closure searches find no V1/opaque runtime
      consumer in these five families, and the focused exact status, quota,
      source, replay, lifecycle, and admission selection passes 50/50.
- [x] Convert method and authority revocation plus same-method replacement to
      atomic exact retirement. The D1 CAS tests prove exact sibling isolation,
      quota closure, hosted-child cleanup, and stable replay for all three
      owning transitions.
- [x] Convert every route in the route policy matrix. Built-in route handlers
      resolve exact operation credentials directly at their request boundary;
      the route-definition policy registry applies only to extension routes.
      Frozen Router A/B discriminators such as `reusable_wallet_session` remain
      wire vocabulary and do not select a V1 persistence or admission path.
- [x] Implement hosted child credentials and exact parent lifecycle handling.
- [x] Update material promotion and exact status readback.

Exit: every server session is direct V2, and core server services receive only
exact admission contexts. No V1 request or persistence resolver remains.

### Phase 3 — Convert browser, SDK, recovery, and device linking

- [x] Delete the temporary client capability and response-family tags from every
      issuance boundary.
- [x] Define the V6 builder/parser and make `replaceExactActive` the only active
      install API.
- [x] Delete V3 writers and curve-token selection; normalize every exact
      response directly to V6.
- [x] Replace wallet-wide active-session reads with an exact selected tuple,
      credential-bound identity, or intentional multi-record result. Let type
      errors and the closure search enumerate remaining callers.
- [x] Quarantine V3/V4/V5 rows during bootstrap and install while preserving
      future versions and unrelated stores.
- [ ] Complete the recipient-bound linked delivery and acknowledgement state
      machine, including local pending prerequisites and recipient-loss recovery.
- [ ] Close the post-promotion recovery crash window with resumable local
      continuity and normal exact login.
- [x] Reconcile all affected browser records after material promotion.
- [x] Bump the host/iframe protocol and remove reusable-session message fields.
- [x] Rename `ReusableWalletSessionMintId` to `WalletSessionMintId` without an
      alias; preserve stored and frozen wire field names.

Exit: the final client reads and writes only V6 active records, supported mixed
versions reach terminal UI states, and device-link/recovery interruption paths
resume without creating a second authority or ceremony.

### Phase 4 — Delete V1 and verify the cutover

- [x] Delete the registration adapter and temporary client capability.
- [x] Delete every V1 request and persistence resolver. The closure-ledger
      searches for reusable issuers/status readers, opaque-token resolvers,
      bridge issuers, legacy mint helpers, and registration token projections
      return no production matches; only immutable migration history remains.
- [x] Apply the enforcement/deletion migration and update table manifests.
- [ ] Delete remaining V1 stores, ports, services, parsers, types, browser
      records, fixtures, guards, and obsolete documentation.
- [ ] Review extracted modules for forwarding-only wrappers, cycles, duplicate
      validators, compatibility re-exports, and single-caller helpers; inline or
      delete them unless they preserve a clear domain boundary.
- [ ] Run the closure ledger and focused acceptance matrix.

Exit: repository code and schema contain only the exact Wallet Session model,
and the closure ledger plus acceptance matrix pass.

## Verification

Tests are selected by invariant and changed boundary. Existing focused tests and
shared branch-specific factories should be extended where they express the
current domain model. Failures are classified under the repository testing
policy before production behavior or fixtures change. Historical V1 assertions
and adapter-only tests are deleted with their retired paths.

### Temporary implementation appendix

This appendix records evidence and exact test/file inventories that influence
implementation decisions. It is updated as work lands and may be removed when
every linked boundary is final. Completed-task marking and coherent commit
boundaries remain execution discipline; they are not architectural acceptance
criteria.

#### Causal baselines

Completed prerequisite evidence:

- [x] `tests/unit/authMenuRecoveryContinuation.unit.test.ts` passed six of six
      at `67bac04e9`, covering automatic Passkey/Google continuation, retry,
      cancellation, and irreversible finalization.
- [x] The intended recovery harness was reconciled with `d3c242eac`:
      `driveHostedPasskeyRecovery` waits for automatic continuation and uses
      **Retry finalization** only after an injected retryable failure.
- [x] Combined Passkey+Email inventory variants exist in both R115 recovery
      intended contracts alongside Passkey-only and Email-only origins.

Remaining causal baseline work:

- [ ] Run `tests/e2e/linked-device.operating-path.test.ts` before changing the
      linked production path. No green composed-run baseline is assumed. Record
      prerequisites, command, current result, and failure classification so a
      pre-existing environment or fixture failure is not attributed to R103F.
      Confirm each cross-factor case begins with the genuine single-method
      source inventory, especially Passkey-only to first-Email enrollment. Use
      `pnpm test:linked-device` for managed state; use
      `pnpm test:linked-device:external` only for an intentionally composed
      external stack and label that evidence separately.
- [x] Rerun `tests/unit/authMenuPasskeyContinuation.unit.test.ts` before using it
      as evidence. Earlier evidence was 13 of 17. Classify the account-sync
      wallet-ID expectation, the Email target callback-publication fixture, and
      the two invalid Google OTP flow-ID fixtures. Update or delete stale
      fixtures; do not add a production compatibility branch for them.
- [x] Repair the three stale flat-`provenanceKind` fixtures in
      `tests/unit/walletRecoverySourceSelection.unit.test.ts` through the shared
      active-authority builder. Production reads `authority.provenance.kind`;
      the comparator remains strict.
- [x] Repair the inline envelope-store stub in
      `tests/unit/passkeyCustodyRouteService.unit.test.ts` so it implements the
      current `listWalletCredentialActivity` boundary before using its
      challenge-replay result as R103F evidence.
- [ ] Run both current R115 recovery contracts with the isolated intended
      runner before changing recovery consumers. Use `pnpm test:intended` for
      a fresh managed D1 root and Vite cache per case, and
      `pnpm test:intended:external` only for a labeled composed-stack run. Add
      the post-promotion, pre-local-publication interruption only as part of the
      R103F change.
- [ ] Exercise real-browser Passkey and configured Google recovery activation
      in every supported browser before removing any target-ready user action.
      In-process tests cannot prove transient browser activation survives the
      async prepare and iframe-to-host boundary.

#### Existing focused test inventory

- [x] `tests/unit/d1AuthorizationCore.unit.test.ts`
- [x] Delete obsolete
      `tests/unit/d1OwnerProofWalletSessionIssuance.unit.test.ts`; its only
      invariant was issuance through the retired opaque-token service.
- [x] `tests/unit/d1WalletAuthMethodStore.unit.test.ts`
- [x] `tests/unit/d1WalletSessionAuthMethodProvenance.unit.test.ts`
- [x] `tests/unit/linkedDeviceManagement.unit.test.ts`
- [x] `tests/unit/walletSessionAuthorizationStatus.unit.test.ts`
- [x] `tests/unit/walletSessionStatusExactAdmission.unit.test.ts`, proving the
      exact quota projection, tuple mismatch, fail-closed absence, and zero V1
      credential/status reads
- [x] `tests/unit/walletSessionExpiry.boundaryAndServer.unit.test.ts`, including
      selected-authority binding and sibling-quota substitution rejection
- [x] Delete obsolete
      `tests/unit/registrationEstablishedWalletSessionProjection.unit.test.ts`,
      which asserted V1 registration curve-token merge and wallet-wide reads;
      direct registration persistence is covered by the V2 replay/parser tests.
- [x] `tests/unit/walletRegistrationActivateRoute.unit.test.ts`, covering direct
      issuance, credential-free same-mint replay, and strict response parsing
- [x] `tests/unit/pendingWalletRegistrationPublication.unit.test.ts`, proving
      issued V6 installation shares the local publication transaction,
      same-method predecessor replacement preserves siblings, late failure
      rolls back every row, and credential-free replay stays pending until V6
      exists.
- [x] `tests/unit/pendingWalletRegistrationRecovery.unit.test.ts`, proving
      startup reconstructs exact Passkey Route 4, validates the committed
      projection, publishes an issued session, and retains credential-free
      replay for exact-method unlock.
- [x] `tests/unit/routerAbEcdsaExactActivationWire.unit.test.ts`, covering the
      exact session/credential response, retired-bearer rejection, ECDSA
      material binding, and removal of client-capability fields
- [x] `tests/unit/syncAccount.yaoOrchestration.unit.test.ts`
- [x] `tests/unit/routerAbEd25519YaoRecoveryWalletSessionAuthorization.unit.test.ts`,
      proving exact active-material admission, threshold-session substitution
      rejection, opaque-token rejection, durable-challenge enforcement despite
      a retired opaque bearer, receipt-path isolation, and zero legacy-store
      reads; obsolete linked-JWT and opaque-bootstrap fixtures were removed
- [x] `tests/unit/walletExecutionAdmissionV2.unit.test.ts`, including exact-only
      device-link owner approval, fail-closed missing-credential behavior, and
      zero legacy reads from both ordinary signing validators
- [x] `tests/unit/walletExecutionLanePreflight.unit.test.ts`, proving exact
      credential admission reaches the owning method without reading the V1
      opaque-token store
- [x] `tests/unit/ecdsaV2PoolFillAdmission.unit.test.ts`, proving linked ECDSA
      pool fill admits the exact operation credential without V1 fallback
- [x] `tests/unit/ecdsaMaterialActivationWalletStore.unit.test.ts`, proving
      exact ECDSA step-up admission, canonical material binding, replacement
      rejection before proof/evidence/admission, and zero opaque-store reads
- [x] `tests/unit/signingSessionSealExactAdmission.unit.test.ts`, proving both
      signer families bind seal authorization to active material and the exact
      threshold-session identity, with mismatch and missing-credential paths
      failing without legacy-store reads
- [x] `tests/unit/thresholdEd25519EcdsaSessionReuseExactAdmission.unit.test.ts`,
      proving exact ECDSA-to-Ed25519 reuse, runtime-policy and sibling-method
      isolation, and fail-closed absence without opaque-token or V1 status reads
- [x] `tests/unit/syncAccountYaoEnrichment.domain.guard.unit.test.ts`
- [x] `tests/unit/nearPublicApi.walletSessionAuthorization.unit.test.ts`,
      proving exact `/near/public-keys` admission and exact selected-tuple
      implicit-account funding; missing or expired sessions fail before fetch
      without legacy session reads
- [x] `tests/unit/webauthnAuthenticatorListing.unit.test.ts`, proving exact
      authenticator inventory admission, RP forwarding, metadata projection,
      and fail-closed absence without legacy opaque-token reads
- [x] `tests/unit/authIdentity.walletSessionAuthorization.unit.test.ts`, proving
      exact identity inventory and mutation, same-method fresh step-up, sibling
      same-wallet rejection before side effects, and no legacy resolver reads
- [x] `tests/unit/walletCustodyEnvelopeOwnershipAdmission.unit.test.ts`,
      proving exact wallet/method forwarding and fail-closed absence without
      legacy opaque-token reads; the sibling production-service assertion is
      in `tests/unit/passkeyCustodyRouteService.unit.test.ts`
- [x] `tests/unit/emailOtpFactorReleaseRoute.unit.test.ts`, proving exact Email
      OTP enrollment and Ed25519-subject admission, fail-closed mismatch and
      absence, zero legacy resolver reads, and the live worker-sealing helper;
      stale tests for removed route-handler exports were deleted
- [x] `tests/unit/walletRegistrationNearFundingAdmission.unit.test.ts`, proving
      exact operation-credential funding, signer-derived implicit-account
      binding, fail-closed absence, and zero legacy resolver reads
- [x] `tests/unit/addAuthMethodSourceClaim.unit.test.ts`, proving a source claim
      uses the selected exact tuple and fails closed when that tuple is absent
- [x] `tests/unit/walletHostOwnerAuthority.unit.test.ts`, proving owner approval
      uses the selected exact tuple and requires a matching unexpired export-root
      capability for delegated key export
- [x] `tests/unit/walletSessionOperationCredential.unit.test.ts`
- [x] `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts`
- [x] `tests/unit/relayWalletRegistration.boundary.unit.test.ts`
- [x] `tests/unit/ed25519YaoSealedRefreshPersistence.unit.test.ts`
- [x] `tests/unit/d1LinkedDeviceAuthorityInstallService.unit.test.ts`
- [x] `tests/unit/d1LinkedDeviceVerifiedLinkSourceReader.unit.test.ts`, proving
      exact-source absence fails closed and combined authorities preserve both
      signer families
- [x] `tests/unit/deviceLinkingRoutes.unit.test.ts`, rerun after exact-only
      source and owner authorization across claim, approval, target credential,
      cancellation, and source-contribution routes
- [x] `tests/unit/linkDeviceAuthorityResume.unit.test.ts`, including production
      bootstrap deferral without V6 and replay once the exact credential is
      available
- [x] `tests/unit/authMenuPasskeyContinuation.unit.test.ts`, preserving the
      terminal retry state when the other device cancels
- [x] `tests/unit/emailOtpEcdsaSigningRefreshRuntimeScope.unit.test.ts`
- [x] `tests/unit/passkeyEd25519YaoWarmRecovery.unit.test.ts`
- [x] `tests/unit/walletRecoverySourceSelection.unit.test.ts`, preserving
      eligibility, registration-authority preference, target-family preference,
      and deterministic creation-time/method-ID tie-breaking
- [x] `tests/unit/walletRecoveryFinalization.unit.test.ts`, preserving additive
      replay and existing continuity authority, method, envelope, and session
- [x] `tests/unit/walletRecoveryFinalizeWire.unit.test.ts`, preserving strict
      active-authority/active-method projections and cross-wallet rejection
- [x] `tests/unit/walletRecoveryGoogleEmailOtpFinalizeRoute.unit.test.ts`,
      preserving strict Email recovery projection and server-owned enrollment
- [x] `tests/unit/walletRecoveryLocalProjection.unit.test.ts`, covering
      interruption and reload across local publication boundaries
- [x] `tests/unit/authMenuRecoveryContinuation.unit.test.ts`, preserving
      automatic continuation, target-ready retry, and non-cancellable
      finalization
- [x] `tests/unit/passkeyCustodyRouteService.unit.test.ts`, proving promotion
      replay returns the same server-read committed authority/method projection
- [x] `tests/unit/scanDevice.firstEmail.unit.test.ts` when linking orchestration
      changes, preserving first-Email routing and release of the iframe
      foreground surface while Device 1 waits
- [x] `tests/unit/qrCodeScanner.progress.unit.test.ts` when scanner/progress UI
      changes, preserving interactive cancellation and opener focus

#### Intended-behaviour and operating-path inventory

- [ ] `tests/e2e/intended-behaviours/passkey.registration.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/email-otp.registration.benchmark.test.ts`
- [ ] `tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/email-otp.unlock.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/passkey.recovery.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/google-email-otp.recovery.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/refactor93-staging-cohort.staging.test.ts`
      registration replay assertion
- [x] `tests/e2e/intended-behaviours/auth-method-addition.matrix.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/passkey.add-email-otp.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/email-otp.add-passkey.contract.test.ts`
- [ ] `tests/e2e/linked-device.operating-path.test.ts` for all four genuine
      source/target factor combinations

#### Required targeted additions and updates

- [x] Direct-V2 atomic issuance failure and replay tests.
- [x] Registration receipt tests proving activation and deferred provisioning
      persist no bearer, child credential, or credential-bearing response.
- [x] Registration cutover-migration tests for both prefixes: known-shape
      credential-free rewrite or deletion, unrelated-row preservation, and
      unknown/unmappable abort.
- [x] Delete compatibility-adapter and adapter-table behavior tests with their
      production issuers, resolvers, fixtures, and runtime manifests. The
      immutable creation migration, explicit drop migration, negative source
      guard, and final schema-deletion proof remain as migration history rather
      than compatibility code.
- [x] Contract update proving Route 3, service comments, and staging assertions
      no longer promise byte-identical credential-bearing replay.
- [x] `already_committed` replay test proving no credential fabrication and
      successor exact unlock retirement. The Ed25519 Route 4 proof in
      `tests/unit/walletRegistrationActivateRoute.unit.test.ts` also verifies
      predecessor quota exhaustion and sibling-method preservation.
- [x] Lost founding-registration response coverage for Passkey and Email OTP
      across page or worker termination. The startup recovery tests rebuild the
      exact Route 4 request from the persisted pending row, validate the
      committed projection, and publish the issued V6 session atomically for
      both founding methods; credential-free replay remains pending for exact
      unlock.
- [x] Mint tests proving same-mint identity replay and fresh-mint replacement.
- [ ] Exact material-resolution tests covering every legacy opaque runtime
      field and rejecting synthesized identities.
- [x] Linked activation tests proving digest, credential, recipient, ciphertext,
      and session stability on replay.
- [ ] Linked loss tests for response loss, failed exact-record write, recipient
      loss, delivery expiry, acknowledgement loss, and acknowledged cleanup.
- [x] Linked recipient/AAD binding and cross-session stale acknowledgement
      tests.
- [ ] Crash injection after delivery tombstone, ciphertext removal, allocation
      deletion, link-session deletion, and cleanup completion.
- [ ] Route test proving acknowledgement after live-session deletion
      authenticates through the cleanup receipt and avoids early `not_found`.
- [ ] Local prerequisite transaction tests covering crash atomicity,
      invisibility, receipt replay, both retryable pending reasons, and terminal
      cleanup that preserves pre-existing records.
- [x] Migration-owned linked-install schema parity test after runtime DDL
      deletion.
- [x] Exact-record type/parser fixtures for required fields and
      session/credential coupling.
- [x] `replaceExactActive` test covering same-method retirement, sibling
      preservation, and late V3/V4/V5 writes.
- [x] Exact-reader tests with two active sibling methods across signing, export,
      funding, refresh, management, readiness, and source claims. Focused
      funding, readiness, and source-claim isolation lives in
      `walletRegistrationNearFundingAdmission.unit.test.ts`,
      `signingSessionReadiness.exactSession.unit.test.ts`, and
      `addAuthMethodSourceClaim.unit.test.ts`; committed signing, export,
      refresh, and management proofs complete the matrix.
- [x] Bootstrap quarantine test for observed V3/V4/V5 rows.
- [x] Shared-IndexedDB tests for future-row preservation, terminal
      `upgrade_required`, legacy-row quarantine, and final-reader containment;
      `tests/unit/walletSessionOperationCredential.unit.test.ts` covers direct
      reads, exact selected-method reads, and replacement.
- [x] Typed lifecycle tests for missing, expired, exhausted, retired,
      method-revoked, authority-revoked, and capability-unavailable results.
      `tests/unit/walletSessionStatusExactLifecycle.unit.test.ts` proves them
      against seeded signer D1 rows;
      `tests/unit/walletSessionStatusExactAdmission.unit.test.ts` proves the
      wire projection each one publishes.
- [x] Authorized-operation full-scope claim and exact replay tests.
- [x] Hosted nominal-type, disjoint-prefix, issue/redeem/use Origin,
      iframe-parent Origin, authoritative wallet-origin, quota, parent lifecycle,
      and primary-preservation tests. The origin suites cover issue, redeem,
      child use, iframe adoption, and authoritative wallet-origin binding;
      `tests/unit/d1WalletSessionAuthMethodProvenance.unit.test.ts` covers
      disjoint credential families, shared quota, parent expiry, exact parent
      resolution, primary preservation, and replacement cleanup.
- [x] Authority/material-promotion tests covering stable identities, all
      affected server snapshots, all same-authority browser records, and lost
      response readback.
- [x] Host/iframe protocol-skew tests in both directions with removed fields
      rejected.
- [x] Targeted IndexedDB cleanup test proving unrelated stores survive.
- [x] Wallet-bootstrap test covering empty, exact, legacy, malformed, and future
      storage without a blank shell. The focused initialization matrix in
      `tests/unit/walletSessionOperationCredential.unit.test.ts` proves the
      explicit result and preservation/quarantine behavior for all five states.
- [x] Exact method- and authority-revocation transaction tests.
- [ ] Additive recovery tests for both targets and source inventories, strict
      committed projections, interruption after promotion, local publication,
      preservation of existing access paths, and one normal exact login.
- [x] Exact-enforcement migration tests for fully scoped V2, rejection of
      partial-scope pending rows, and deletion of all-null-scope V1 pending rows.
- [x] Clean-database and current-history migration tests covering abort on
      usable duplicates, deterministic retirement of unusable/expired rows, and
      zero foreign-key-check results.
- [x] Update Router A/B Wallet Session claim fixture helpers.
- [x] Delete stale inline JWT-shaped Wallet Session fixtures found by closure
      searches. The remaining signing, funding, export, and presignature tests use
      the final opaque operation-credential bearer shape; the obsolete mock
      `mintWalletSession` producer was deleted. Negative persistence fixtures that
      deliberately prove `walletSessionJwt` rejection remain as hostile inputs.

### Acceptance matrix

| Risk | Required proof |
| --- | --- |
| Direct issuance | Passkey and Email OTP registration each reach immediate NEAR and EVM-family signing |
| Lost registration response | Page/worker termination after server commit resumes from pending local commit, receives `already_committed`, publishes local state atomically, unlocks, and signs |
| Credential persistence | Both completion prefixes contain no credential; exposed usable bearers are retired or expired; unrelated rows remain unchanged |
| Unlock and step-up | Lock/reload reaches exact-method unlock and immediate signing; key export requires fresh exact-method step-up |
| Exact replacement | Same-method predecessor and quota retire while a sibling method remains active |
| Exact admission | Both curves reject V1 fallback; missing, expired, exhausted, retired, and revoked states are typed |
| Revocation | Exact method revocation preserves sibling methods; authority revocation affects only the owned sessions, quotas, and children |
| Material identity | Signing and export use the capability subject's exact material activation with no synthesized runtime IDs |
| Device linking | All four genuine source/target factor combinations sign and expose export on Device 2 without a second unlock |
| Linked replay and loss | Lost response, failed local write, recipient loss/expiry, lost acknowledgement, and crash after each cleanup transition resume exactly |
| Recovery | Both targets preserve all prior access paths; interruption after promotion resumes local continuity without another code; normal login issues one exact session |
| Hosted handoff | Child works only for authoritative stored origins, shares parent quota, preserves primary credential, and fails with parent lifecycle |
| Promotion | Every affected same-authority server and browser projection updates before runtime activation; lost response reconciles through exact status |
| Shared IndexedDB | Final readers quarantine V3/V4/V5, preserve future rows, and make empty, exact, legacy, malformed, and future states reach explicit UI |
| SDK/iframe protocol | Old/new skew fails in both directions before port adoption or readiness |
| Migration | Clean and current-history database fixtures pass; usable duplicates and foreign-key results abort deletion |
| Closure | Every boundary matrix row is final, every temporary path is deleted, and all legacy searches are clean |

Run the narrowest focused units, type fixtures, and intended-behaviour contracts
that cover the changed rows. Broader repository gates follow only when the user
authorizes them.

## Closure ledger

The following searches must have no production matches except immutable
historical migrations, frozen protocol vocabulary, and historical refactor
documentation:

```bash
rg -n "reusable_wallet_sessions|opaque_wallet_session_tokens" \
  packages crates wasm apps

rg -n "issueReusableWalletSession|readReusableWalletSessionStatus|\
resolveOpaqueWalletSessionToken|issueOpaqueWalletSessionToken|\
readOpaqueWalletSessionTokenByIdentity" packages

rg -n "not_v2|readActiveForWallet|wallet_session_authorization_v3|\
WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4|\
WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5" packages apps

rg -n "issueWalletSessionAuthorizationV2FromReusableSession|\
refreshWalletSessionAuthorizationV2FromReusableSession|\
projectReusableWalletSessionV2" packages

rg -n "mintRouterAbEd25519YaoWalletSessionV1|\
issueRouterAbEd25519OpaqueWalletSessionToken|walletSessionPolicyMintId|\
ReusableWalletSessionMintId|parseReusableWalletSessionMintId" packages

rg -n "registration_established_wallet_session_v1|\
RegistrationEstablishedSessionTokens|walletSessionTokenForCurve" \
  packages apps

rg -n "operation_credential_hash =|\
putWalletSessionAuthorizationV2OperationCredential|\
issueWalletSessionAuthorizationV2OperationCredential" \
  packages/wallet-server/src

rg -n "walletSessionClientCapability|\
direct_exact_response_future_record_tolerant" packages apps
```

The singular Router A/B `reusable_wallet_session` discriminator and the applied
`consume_reusable_wallet_session` quota discriminator remain frozen protocol
vocabulary. Console-session JWT types also remain.

Database closure is proved on clean and current-history migration fixtures. The
final exact-session boundary retains
`linked_device_wallet_session_credential_deliveries_v1`; its suffix names the
delivery record version and does not identify a legacy Wallet Session surface.

- no V1 Wallet Session, opaque-token, replay-adapter, or hosted-exchange table
  remains;
- no unscoped pending operation remains;
- no active null-digest V2 session remains;
- no credential-bearing completion row remains;
- no usable exact-tuple duplicate remains;
- `PRAGMA foreign_key_check` returns zero rows; and
- no V1 session/token/hosted-exchange compatibility trigger, view, or alias
  remains after enforcement.

R103F is complete when every boundary-matrix row is in its final state, every
temporary compatibility path has been deleted, the acceptance matrix passes,
and the code and database closure ledgers are clean.

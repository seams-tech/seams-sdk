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
implementation is in progress. Every temporary compatibility path named here
has a removal gate. Document and production line counts are diagnostic only;
neither is a completion criterion.

The invariants, boundary matrix, implementation phases, rollout state machine,
and closure ledger are coordinated views in this one plan. The detailed
inventory supplies task-level status beneath those views.

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
    future rows. The precursor and final SDKs both reach explicit terminal UI
    states under version skew.
15. The host SDK and iframe agree on `WALLET_PROTOCOL_VERSION` before adopting
    the port or exchanging Wallet Session data.
16. Compatibility remains confined to the named request, IndexedDB, and D1
    persistence boundaries. Each compatibility branch is deleted at its gate.
17. Applied migrations remain byte-for-byte unchanged. The final schema has no
    V1 table, trigger, view, or alias.

## Boundary matrix

Each row is a completeness obligation and one view of this authoritative plan.
Implementation phases refer to these IDs instead of restating their designs.
Typed call sites are enumerated by narrowing or deleting the old types and APIs.
The temporary implementation appendix owns exact file/call-site lists while a
phase is active.

| ID | Boundary | Producer(s) | Consumers | Replay / recovery | Persistence and final shape | Compatibility and deletion gate | Primary proof |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | D1 authorization persistence | Direct issuer and authority-activation CAS | Admission, status, quota, replay, revocation, hosted children | Full-scope mint replay returns committed identity | V2 authorization, quota, and primary digest commit atomically | Bridge workers may read V1 tables; delete after zero active V1 state and exact-only workers | Failure injection plus migration checks |
| B2 | Session issuance | Registration, unlock, refresh, sync, linked activation, post-recovery login | Browser installers, signing runtimes, status | `issued` / `already_committed`; unlock replaces unreachable committed session | Direct V2 response and credential digest | Registration old-response adapter only; delete when pending-commit clients own replay | Issuance matrix and same-mint tests |
| B3 | Registration completion | Registration activation and deferred provisioning | Registration client, replay route, local discovery/install transaction | Pending local commit plus credential-free committed projection | `WalletRegistrationSessionCommitReceiptV2`; bounded adapter digests live only in the temporary replay table | Adapter attaches ephemeral V1 bearer; delete its table and resolver when `already_committed` is authoritative | Lost response through immediate signing |
| B4 | Operation admission | Primary and hosted credential resolvers | Both curve validators, pool fill, seal, preflight, warm recovery, step-up | Authorized-operation replay resolves the same exact context | Required V2 credential reader and typed admission union | Bridge request resolver accepts issued V1 bearers; delete after credential and pending-operation drain | Both curves reject fallback |
| B5 | Runtime material resolution | Capability-subject material repository | Router A/B requests, signing, export, pool fill | Re-resolution uses the same activation identity | Exact `MpcMaterialActivationRef` projection | No compatibility; delete or replace every opaque-binding consumer | No synthesized runtime IDs |
| B6 | Status, quota, and source activity | Exact status and authorization stores | Browser reconciliation, quota, operation replay, lifecycle UI | Full digest-free projection repairs lost promotion response | Exact V2 scope and typed lifecycle | All-null-scope old-worker rows remain readable; delete after pending V1 operation count reaches zero | Full-scope replay and lifecycle tests |
| B7 | Revocation and replacement | Method, authority, replacement, and budget CAS operations | Admission, status, hosted children, sibling sessions | Exhausted identity remains readable for typed step-up | Exact session, quota, and child lifecycle update together | V1 cleanup remains at bridge persistence boundary; delete after zero active V1 | Transaction tests |
| B8 | Browser persistence | Registration, unlock, refresh, sync, recovery, device-link installers | Signing surface, login, readiness, step-up, management, public API | Bootstrap and exact status reconcile stale projections | One V6 record selected by exact tuple | Precursor writes V5 and readers contain late legacy writes; enable V6 after unmarked-client drain | Mixed-version IndexedDB tests |
| B9 | Host SDK and iframe | Host CONNECT and iframe READY handshakes | Host applications, iframe router, hosted child cache | Version mismatch is terminal and retryable after upgrade | Matching protocol version and exact message shapes | No message adapter; known embeds upgrade before final iframe | Both skew directions fail closed |
| B10 | Hosted handoff | Hosted issue and redemption routes | Iframe child cache and child-authorized HTTP routes | Single-use exchange; child resolves exact parent | Origin-bound `wsh_` digest record with parent FK | Existing V1 exchanges drain; delete after unconsumed count reaches zero | Origin, parent lifecycle, and primary-preservation tests |
| B11 | Device-link activation | Device 2 preparation and server activation CAS | Local installer, runtime activation, acknowledgement | Activation replay returns original recipient-bound ciphertext and session | Exact session plus sealed delivery row | Existing pending link/session states remain retryable; delete V1 support after drain | Four factor paths plus loss/replay tests |
| B12 | Device-link acknowledgement | Device 2 durable intent and acknowledgement route | Delivery cleanup, allocation cleanup, link cleanup, bootstrap replay | Cleanup receipt authenticates replay after live-session deletion and completion | One idempotent acknowledgement lifecycle | Live link authenticates until deletion; retain the receipt through the bounded post-completion replay window | Crash after every transition |
| B13 | Recovery | R115 finalization and replay | Local continuity publisher, ordinary exact login | Reload resumes committed target projection without another code | Additive server projection plus non-discoverable local commit | Existing response projection remains authoritative; local pending state publishes or fails closed | Interruption after promotion for both targets |
| B14 | Material promotion | Authority-promotion CAS and exact status | Every affected server snapshot, browser sibling record, promoted runtime | Status read repairs a lost promotion response | Updated digest/subjects with stable session identities | No compatibility; runtime waits for complete reconciliation | Lost-response and sibling-method tests |
| B15 | Management and read routes | Request credential resolver | Route policy matrix consumers | Each replay retains the original exact scope and assurance | Exact admission context only in core services | Request boundary accepts issued V1 during drain; delete with V1 credential resolver | Route policy tests |
| B16 | Public/shared types | Server responses, IndexedDB parsers, iframe protocol | SDK, browser, generated bindings, tests | Boundary parsers reject removed and cross-family shapes | Exact server, credential, browser, and iframe unions | Rollout-stage parsers only; delete after final SDK and exact-only worker | Type fixtures and closure searches |

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

### Untyped and deployment-visible inventories

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
| `reusable_wallet_sessions` | Drain active rows, then drop table, indexes, and triggers |
| `opaque_wallet_session_tokens` | Retire exposed usable bearers, drain remaining rows, then drop |
| `registration_replay_opaque_wallet_session_tokens_v1` | Keep adapter digests for at most five minutes, require active parent session/quota, then require zero rows and drop with the adapter |
| V2 rows with null credential digest | Treat as unusable; retire before enforcement |
| All-null-scope pending operations | Read through the bridge boundary until their count reaches zero |
| V1 hosted exchanges | Permit bounded redemption, then require zero unconsumed rows |
| V1-only quotas | Retain while referenced; delete unreferenced rows during enforcement |
| Registration completion rows | Rewrite to credential-free receipts or delete when replay state is unnecessary |
| Capability-tagged receipts | Normalize to final `already_committed`, then require zero tags |
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
| Shared IndexedDB tabs | Precursor, final, malformed, legacy, and unknown-future records are exercised |
| Deployed clients and workers | Rollout gates cover old clients, old tabs, old workers, and host/iframe skew independently |

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

One bounded compatibility release deploys the receipt writer, strict parser,
and old-client response adapter together. The adapter reconstructs the stable
committed projection and signs a V1 bearer in memory with a maximum five-minute
lifetime. Its digest is stored in a dedicated registration-replay adapter table
bound to the receipt operation, exact V1 session, quota, authority, auth method,
curve, and runtime binding. The ordinary opaque-token table keeps its existing
one-token-per-wallet-session/curve invariant, and a late original response or
another old tab is not invalidated by replay response ordering. Adapter-token
resolution requires the parent session and quota to remain active and rejects
the token after its own earlier expiry. Session retirement, auth-method cleanup,
identity lookup, and expiry cleanup cover both token tables. Plaintext is never
persisted. Concurrent identical replay returns usable responses; conflicting
replay fails closed. Bearer bytes may differ while the fingerprint and committed
projection remain stable. The legacy response's top-level `expiresAtMs` reports
the adapter bearer expiry so an old client never persists the underlying session
lifetime as the bearer's usable lifetime. The adapter table, its resolver, and
its tests are deleted together when the pending-commit client owns terminal
replay.

Existing successful registration completion rows under both activation and
deferred-provisioning prefixes may contain plaintext V1 bearers. These are
`wallet-registration-activate:` and
`wallet-registration-near-provisioning:` records in
`router_ab_yao_versioned_json_records`. A bounded D1 remediation command must:

1. run only after no old completion writer serves traffic and the maximum
   in-flight request window has elapsed;
2. select only the two known registration prefixes;
3. parse known completion shapes without logging row bodies;
4. hash each bearer through the production digest function and retire a matching
   usable V1 session/token;
5. rewrite the row to the credential-free receipt or delete it when replay state
   is unnecessary;
6. preserve unrelated records and abort on unknown or unmappable shapes; and
7. record before/after counts and repeat the zero-credential query after the
   in-flight window.

D1 backup/time-travel retention is recorded separately. The exposure remains
open until affected credentials are retired or expired across retained copies,
or an approved platform purge completes.

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

### Shared IndexedDB and SDK/iframe release boundaries

The precursor SDK consumes the direct exact issuer response, persists the
existing V5 representation, and preserves unknown future Wallet Session rows.
It reaches `upgrade_required` when its own usable session cannot continue.

Every session-issuing boundary temporarily requires:

```ts
walletSessionClientCapability:
  'direct_exact_response_future_record_tolerant'
```

The capability proves that the client parses the direct response and preserves
future IndexedDB versions. It is normalized at request boundaries, remains
outside ceremony and mint fingerprints, and is recorded in durable operation
receipts only to preserve replay response family. Missing or changed replay
capability returns a typed protocol mismatch without rotating credentials.

After capability enforcement, unmarked clients may use existing sessions during
the bounded drain and cannot mint, refresh, or replace them. The first V6 write
waits for the last unmarked session lifetime to drain or an approved
invalidation. Before deleting the capability parser, every tagged durable
receipt is normalized to the final credential-free `already_committed`
projection and the tagged count reaches zero.

Final readers quarantine V3/V4/V5 rows observed during bootstrap or install,
including late writes by an already-open precursor tab. R103F retains the
current IndexedDB keyPath and does not bump `SEAMS_WALLET_DB_VERSION` while its
upgrade function deletes every object store. A keyPath change requires
`versionchange` and remains outside this cutover. A precursor that sees an
unknown future row reaches `upgrade_required`; it never reports that row as
`corrupt`.

Registration, unlock, sync, recovery, and link responses may retain family-
specific signer-runtime bootstrap metadata. Those bootstraps contain no Wallet
Session bearer. One exact browser record authenticates the capability subjects;
each bootstrap remains bound to its own material activation and threshold
runtime identity.

The npm host SDK and deployed iframe also form a release boundary. CONNECT
carries the host protocol version. The iframe validates it before adopting the
port. READY carries the iframe version, which the host validates before marking
the connection ready. Either skew direction returns
`WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` before Wallet Session data crosses the
`postMessage` boundary. On a bad CONNECT version, the iframe reports its own
version through the transferred port, closes the port, and never adopts it.
This lets SDKs with the current READY validator fail with the stable mismatch;
older SDKs without that validation still receive no adopted channel. Known
embedding applications must upgrade with the final iframe.

### Hosted child credentials

`wallet_session_hosted_credentials_v2` stores the exact parent identity, child
credential digest, application and wallet origins, expiry, and lifecycle. The
exchange code is single-use. Child expiry never exceeds parent expiry.

Issue requires the actual request `Origin` to equal `appOrigin`. The requested
`walletOrigin` must equal authenticated tenant deployment metadata or an
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
- [ ] Extract exact-session reader logic from `login.ts` and
      `BrowserSigningSurface.ts` as I8 converts their callers.
- [ ] Regenerate the exact `readActiveForWallet` consumer inventory before I8.
      The previous checkpoint found 44 call sites across 18 production consumer
      files; the generated current list controls the conversion work.
- [ ] Record the final V2 issue, persistence, read, admission, retirement, and
      replay APIs that remain after deletion so the closure search distinguishes
      the intended exact surface from a missed legacy replacement.

Behavior-neutral extraction, legacy deletion, and behavior changes should use
coherent commits where practical. An extraction that touches more than five
existing files, creates a forwarding compatibility wrapper, widens a domain
input, or invents a new layer is deferred until its operating path works.

### I1 — Server V1 persistence and service surface (B1, B6, B7)

- [ ] Delete `readReusableWalletSessionStatus` from
      `d1AuthorizationStore.ts`, `authorization/service.ts`, and
      `authServicePort.ts`.
- [ ] Delete `putWalletSessionAuthorization` and its V1 readback helpers.
- [ ] Delete `issueReusableWalletSession` and its preparation/domain inputs.
- [ ] Delete the V1 `readWalletSessionAuthorizationByMint`; narrow the V2
      reader around full scope, exact method, and `WalletSessionMintId`.
- [ ] Delete `revokeReusableWalletSessionsForAuthMethod` and its prepared SQL
      statement builder.
- [ ] Delete `putOpaqueWalletSessionToken`.
- [ ] Delete `readOpaqueWalletSessionToken`.
- [ ] Delete `readOpaqueWalletSessionTokenByIdentity`.
- [ ] Delete `issueOpaqueWalletSessionToken` and
      `resolveOpaqueWalletSessionToken` from the service and route port.
- [ ] Delete `ResolvedOpaqueWalletSessionToken`, legacy curve-binding types,
      and pre-provenance runtime branches that depend on those APIs.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`
- `packages/wallet-server/src/authorization/service.ts`
- `packages/wallet-server/src/router/framework/authServicePort.ts`
- `packages/wallet-server/src/authorization/domain.ts`

### I2 — Direct V2 issuance, registration replay, and promotion (B1, B2, B3, B14)

- [ ] Delete `issueWalletSessionAuthorizationV2FromReusableSession`.
- [ ] Delete `refreshWalletSessionAuthorizationV2FromReusableSession`.
- [ ] Delete `projectReusableWalletSessionV2` and its projection types.
- [ ] Replace separate session and credential writers with one issuer that
      prepares `{ session, quota, primaryCredential, credentialDigest }`.
- [ ] Delete `putWalletSessionAuthorizationV2OperationCredential` and
      `issueWalletSessionAuthorizationV2OperationCredential`; no production API
      may update `operation_credential_hash` after session insertion.
- [x] Persist the session, quota, and primary digest in one batch or owning
      authority-activation CAS before returning success.
- [ ] Rebuild V2 in the enforcement migration so an active row requires a
      non-null primary digest.
- [ ] Make same-method replacement retire its predecessor session, close its
      quota, and retire hosted children in the successor transaction.
- [ ] Add the full-scope exact-tuple partial unique index after deterministic
      duplicate preflight.
- [x] Preserve historical `mint_id` uniqueness; every replacement receives a
      fresh mint and policy-derived mint helpers are deleted.
- [x] Make the V2-by-mint reader accept the narrow replay key and return the
      committed exact identity without reconstructing the expected record.
- [x] Implement `issued` and `already_committed` without credential rotation or
      fabrication.
- [x] Persist `PendingWalletRegistrationCommitV1` before the terminal request;
      keep it sufficient for reload and invisible to normal discovery.
- [ ] Change final registration replay to credential-free committed projection
      plus `unlock_exact_method`.
- [ ] Validate replay against the pending record and atomically publish profile,
      authenticator, authority, method, signer/account state, and selection.
- [x] Implement the nine-store publication primitive: re-read the exact pending
      row in-transaction, validate Passkey/Email OTP and founding identities,
      roll back all local state on failure, and retain mixed activation pending
      state until deferred NEAR publication.
- [x] Replace activation and deferred-provisioning completion rows with
      `WalletRegistrationSessionCommitReceiptV2`.
- [ ] Use one committed installation projection for compatibility replay and
      final pending-commit recovery.
- [ ] Keep one bounded old-client adapter that attaches a V1 bearer only in
      memory; delete it when `already_committed` becomes authoritative.
- [x] Add a dedicated adapter-only digest table with a maximum five-minute token
      lifetime and exact receipt/session/quota/method/runtime binding. Extend
      resolution and cleanup without weakening the ordinary opaque-token
      table's unique wallet-session/curve constraint.
- [x] Update Route 3 comments and tests from byte-identical bearer output to
      stable fingerprint and committed-projection identity.
- [x] Make the receipt parser reject bearer fields, credential-bearing
      bootstraps, local secrets, and generic persisted response payloads.
- [ ] Remediate historical completion rows under both registration prefixes
      and retire any mapped usable bearer before rewriting or deletion.
- [ ] Update material promotion so the authority CAS refreshes every affected
      non-retired V2 snapshot while preserving session identity.
- [ ] Extend authenticated exact status to return the complete digest-free
      projection used for promotion-response loss and bootstrap reconciliation.

Convert every current issuer:

- [ ] founding registration in `d1WalletRegistrationService.ts`;
- [ ] registration session replay/reuse in `d1WalletRegistrationService.ts`;
- [ ] Wallet Session budget refresh in `d1WalletRegistrationService.ts`;
- [ ] linked Ed25519 activation in `d1WalletRegistrationService.ts`;
- [x] active unlock in `d1RouterApiAuthService.ts`;
- [ ] sync bootstrap in `syncAccountBootstrap.ts`;
- [ ] ECDSA post-registration activation in `thresholdEcdsa.ts`;
- [ ] `mintRouterAbEd25519YaoWalletSessionV1` and its sync/registration callers;
- [ ] `issueRouterAbEd25519OpaqueWalletSessionToken` and every direct caller;
      and
- [ ] recovery or device-link issuers found by the final searches.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationService.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration.ts`
- `packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary.ts`
- `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService.ts`
- `packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationEstablishedSessionIssuer.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/syncAccountBootstrap.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- `packages/wallet-server/src/core/threeRouteRegistrationContracts.ts`
- `packages/shared-ts/src/utils/registrationEstablishedSession.ts`

Live issuer symbols include `RegistrationEstablishedSessionIssuerAuthorizationService`,
`issueRegistrationEstablishedGrant`, both registration replay functions,
`issueSyncAccountBootstrapV1`, `handleStrictEcdsaSessionActivation`, the
budget-refresh and linked-activation `issue_wallet_session_v1` branches, and
`mintRouterAbEd25519YaoWalletSessionV1`.

### I3 — Exact operation admission and runtime binding (B4, B5)

- [ ] Make `readWalletSessionAuthorizationV2ByOperationCredential` required in
      `authServicePort.ts`.
- [ ] Delete `WalletSessionOperationCredentialResolution.kind === 'not_v2'`.
- [ ] Keep `resolveOpaqueOwnerWalletSessionAdmission` reachable only from the
      bridge request resolver, then delete it at R4.
- [ ] Delete the Ed25519 validator's V1-token fallback.
- [ ] Delete the ECDSA validator's V1-token fallback.
- [ ] Make operation kind required for reusable-operation admission.
- [ ] Delete the `operationKind === null` ECDSA branch.
- [ ] Convert operation step-up identity resolution in
      `routerAbPrivateSigningWorker.ts`.
- [ ] Convert signing-session seal authorization in `createFetchRouter.ts`.
- [ ] Convert Ed25519 reuse of an ECDSA V1 session in `thresholdEd25519.ts`.
- [ ] Convert ECDSA pool-fill admission in `thresholdEcdsa.ts`.
- [ ] Convert recovery warm-session authorization in
      `routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`.
- [ ] Resolve the capability subject's exact material activation before either
      curve constructs a Router A/B request.
- [ ] Assign every `OpaqueOwnerWalletSessionBinding` field to the authoritative
      material resolver or delete its consumer, including
      `thresholdSessionId`, `participantIds`, `keyManifestDigestB64u`,
      `relayerKeyId`, `runtimePolicyScope`, `keyHandle`, and
      `authorizationSessionId`.
- [ ] Reject any path that substitutes a Wallet Session or authorization ID for
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
`resolveOpaqueOwnerWalletSessionAdmission`, `validateOwnerWalletSessionV1`,
`resolveRouteOpaqueOwnerWalletSession`,
`authorizeSigningSessionSealWithOpaqueWalletSession`, and
`authorizeOpaqueOwnerRecovery`.

### I4 — Status, replay, quota, and source activity (B6)

- [ ] Make `/wallet/session/status` resolve only exact operation credentials in
      the final worker.
- [ ] Return the complete digest-free authorization and quota lifecycle from
      the active status branch.
- [ ] Validate immutable authorization, Wallet Session, quota, authority, and
      method identities against the credential-bound request.
- [ ] Reconcile stale browser records during bootstrap and after lost promotion
      responses before publishing the promoted runtime.
- [ ] Return typed missing, expired, exhausted, retired, authority-unavailable,
      method-unavailable, and capability-unavailable results from persistence.
- [ ] Convert fully scoped `isAuthorizedOperationSourceActive` rows to V2 exact
      lookup.
- [ ] Retain the all-null-scope V1 branch only for pending rows written by old
      workers and delete it at R4.
- [ ] Replace quota lookup through `reusable_wallet_sessions` with the V2
      authorization's `quota_id`.
- [ ] Populate `linked_scope_org_id`, `linked_scope_project_id`, and
      `linked_scope_env_id` on every new grant and reject partial scope.
- [ ] Supersede the applied exact-only `0024` trigger with the additive bridge
      trigger, then remove the V1 branch during enforcement.
- [ ] Require authorized-operation replay to resolve the exact authorization
      that admitted first execution and reject scope, method, authority, quota,
      capability, or material disagreement.
- [ ] Remove V1 status calls from Ed25519 reuse and ECDSA activation.

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

- [ ] Retire V2 authorizations by exact auth-method ID during method revocation.
- [ ] Retire V2 authorizations by exact authority during linked-device
      revocation.
- [ ] Append exact session retirement, quota closure, and hosted-child
      retirement to the owning revocation CAS.
- [ ] Convert explicit session retirement to close the exact V2 session and
      quota and retire hosted children in one transaction.
- [ ] Transition a consumed quota to exhausted through V2 while retaining exact
      identity for typed status and step-up.
- [ ] Replace `hasActiveWalletSessionsForAuthMethod` with a V2 query.
- [ ] Delete duplicate V1 revocation statement builders in
      `d1WalletAuthMethodStore.ts`.
- [ ] Convert additive recovery finalization and replay session checks to the
      exact model while preserving every pre-existing access path.
- [ ] Preserve strict server-read recovery projections for active recovery
      authority and target method on both target branches.
- [ ] Validate wallet, authority, method, target, digest, enrollment, and
      lifecycle relationships at the response boundary.
- [ ] Preserve provenance dispatch: `wallet_registration` and
      `wallet_recovery` use ordinary exact unlock; only `device_link` uses
      linked unlock.
- [ ] Make recovered Email OTP unlock require the exact locally installed active
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
- [ ] Keep wallet lock local to browser record/runtime disposal; remote
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

- [ ] Delete the opaque-token fallback from
      `d1LinkedDeviceVerifiedLinkSourceReader.ts`.
- [ ] Require the exact V2 source session for owner approval.
- [ ] Require the exact operation credential in execution-lane preflight.
- [ ] Add the P-256 ECDH delivery recipient to target preparation and bind it to
      the verified link.
- [ ] Persist Device 2 profile, authenticator, method/factor, authority,
      signer-material state, receipt, and selection as one invisible
      `pending_local_install` transaction before activation.
- [ ] Make local pending replay idempotent by receipt identity and terminal
      cleanup preserve any pre-existing record.
- [ ] Preserve `server_worker_activation_pending` and
      `wallet_session_issuance_pending` as retryable states that allocate no
      second authority.
- [ ] Make resume finalize a locally pending method as active before credential
      decrypt.
- [ ] Commit authorization, quota, credential digest, authority/method
      activation, and one complete sealed-delivery row in the activation CAS.
- [ ] Add exact composite foreign keys to the linked installation and V2
      authorization plus unique full-scope link and digest identities.
- [ ] Bind canonical AAD to tenant scope, link, wallet, authority, method,
      authorization, Wallet Session, quota, credential digest, recipient, issue
      time, and expiry.
- [ ] Define the installation-receipt digest over one canonical logical shape,
      excluding IndexedDB bytes and plaintext credential bytes.
- [ ] Make activation replay return the original sealed delivery, recipient,
      digest, and exact session without minting or overwriting.
- [ ] Order Device 2 as decrypt, validate exact identities, persist V6, activate
      runtimes, record acknowledgement intent, and acknowledge.
- [ ] Extend acknowledgement with authorization ID, Wallet Session ID,
      credential digest, and installation-receipt digest.
- [ ] Reject cross-session or stale acknowledgement before consuming delivery.
- [ ] Implement one idempotent acknowledgement lifecycle covering delivery
      tombstone, ciphertext removal, allocation deletion, link-session deletion,
      and completion.
- [ ] Delete or fold any parallel sealed-delivery cleanup that could race the
      acknowledgement lifecycle.
- [ ] Retain a bounded Device 2 authentication binding in the cleanup receipt;
      bind Device 2 credential, link session, authority, package set,
      authorization, Wallet Session, credential digest, and receipt digest, and
      resolve it before requiring a live link session.
- [ ] Persist pending acknowledgement intent locally and replay it during
      bootstrap until cleanup completes; then clear the intent together with
      the local delivery-resume record.
- [ ] Recover recipient-handle loss or delivery expiry through durable local
      install plus exact-method unlock, without resealing or relinking.
- [ ] Preserve interactive cancellation across `claimed`,
      `awaiting_target_factor`, `awaiting_source_contribution`, and
      `provisioning`. Device 1 retains its owner-authenticated cancellation
      identity and targets the authenticated current revision, Device 2 emits
      one terminal `cancelled`, and the hosted menu reaches an explicit retry
      state with opener focus restored. Postcommit local installation and
      active sessions remain outside that route.
- [ ] Delete `INSTALLATION_SCHEMA_SQL` and other runtime `CREATE TABLE` strings from
      `d1LinkedDeviceAuthorityInstallService.ts` after migration ownership.
- [ ] Move `linked_device_authority_allocations` to the additive migration while
      preserving immutable `0018` ownership of
      `linked_device_authority_installations` and its
      `target_factor_verified_at_ms >= 0` constraint.
- [ ] Verify signing, export, account menus, and inventory immediately after
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

- [ ] Back hosted issue and redemption with an origin-bound V2 child credential
      that resolves one parent, shares its quota, and preserves the primary.
- [ ] Give primary and child credentials separate nominal types, `wst_`/`wsh_`
      encodings, parsers, tables, and lookup branches.
- [ ] Make hosted issue accept `{ appOrigin, walletOrigin }`, redemption accept
      `{ exchangeCode, nonce, appOrigin, walletOrigin }`, and success return the
      parent Wallet Session ID, one hosted child credential, and its expiry.
- [ ] Remove `curve` and `walletSessionToken` from exact hosted wire shapes.
- [ ] Require issue request Origin to equal `appOrigin`.
- [ ] Require requested `walletOrigin` to equal authenticated tenant deployment
      metadata or a server allowlist entry.
- [ ] Require redemption and child-authorized HTTP Origin to equal stored
      `walletOrigin`, and all supplied origins to equal the exchange row.
- [ ] Cache a hosted child in the iframe only when adopted parent origin equals
      stored `appOrigin`.
- [ ] Add the parent composite foreign key and unique child digest.
- [ ] Retire hosted children during parent replacement, explicit retirement,
      method revocation, and authority revocation; enforce parent expiry during
      resolution.
- [ ] Convert the iframe hosted-session cache from per-curve token maps to one
      audience-bound child credential.
- [ ] Convert Email factor-release `wallet_session` admission.
- [ ] Convert `/auth/identities` link/unlink admission.
- [ ] Convert `/near/public-keys` admission.
- [ ] Convert `/webauthn/authenticators` admission.
- [ ] Convert custody-envelope ownership upgrade admission.
- [ ] Convert registration funding/session admission.

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

- [ ] Delete the V3 `WALLET_SESSION_AUTHORIZATION_RECORD_VERSION`.
- [ ] Delete `ActiveWalletSessionAuthorizationProjection` and its retired V3
      sibling.
- [ ] Delete `WalletSessionAuthorizationTokenBundle`.
- [ ] Delete curve token/ID extractors and V3 builders, parsers, serializers,
      merges, and retirement helpers.
- [ ] Delete V3 `replaceActive`, `createOrMergeExactActive`, and
      `upsertActiveWithCurveMerge` behavior.
- [ ] Delete `readActiveForWallet`.
- [ ] Delete `persistActiveWalletSessionAuthorizationCurve` and
      `persistActiveWalletSessionAuthorizationFromRegistration`.
- [ ] Delete the V3 ECDSA bootstrap projection.
- [x] Correct the V5 precursor so its physical `wallet_session_id` is the
      operation credential's Wallet Session ID, reject key/credential drift,
      and preserve same-wallet sibling methods during exact replacement.
- [ ] Define one branch-specific V6 builder and one strict parser requiring
      exact identities, subjects, lifecycle, and primary credential.
- [ ] Reject session/credential mismatch at parsing and before IndexedDB write.
- [ ] Preserve `wallet_session_id` as the Wallet Session keyPath, store
      `authorization_id` separately, and cross-check both.
- [ ] Make exact `replaceExactActive` the only active install API with
      same-method retirement and sibling preservation in one transaction.
- [ ] Quarantine known V3/V4/V5 rows, reject malformed V6, preserve unknown
      future rows, and contain late legacy writes in every reader/install.
- [ ] Remove only obsolete Wallet Session rows; preserve every unrelated wallet,
      authority, method, signer-material, export-root, and recovery-code store.
- [ ] Publish the future-row-tolerant precursor before any V6 production write.
- [x] Define the exact rollout client-capability literal and boundary parser;
      reject omission separately from invalid, aliased, or non-canonical values.
- [ ] Add the temporary client capability to every issuance boundary, record
      replay family, drain unmarked issuance, normalize tagged receipts, and
      delete the capability.
- [ ] Retain the existing DB version and keyPath while the general upgrade
      function remains destructive.

Convert every reader or legacy writer:

- [ ] `BrowserSigningSurface.ts`;
- [ ] `login.ts`;
- [ ] registration legacy persistence in `registration.ts`;
- [ ] recovery/sync legacy persistence in `syncAccount.ts`;
- [ ] `SigningSessionCoordinator.ts`;
- [ ] `PasskeyMpcSessionManager.ts`;
- [ ] `session/availability/readiness.ts`;
- [ ] `clientSessionPersistence.ts`;
- [ ] `ecdsaLoginPrefill.ts`;
- [ ] `routerAbEd25519WalletSessionState.ts`;
- [ ] `signingFlowRuntime.ts`;
- [ ] `emailOtpSigningSession.ts`;
- [ ] `emailOtp/ecdsaLogin.ts`;
- [ ] `browserSigningSurfaceAssembly.ts`;
- [ ] `createBrowserRecoveryPublicDeps.ts`;
- [ ] `stepUpRuntime.ts`;
- [ ] `ed25519YaoWarmRecovery.ts`;
- [ ] `addAuthMethodSourceClaim.ts`;
- [ ] `walletHostOwnerAuthority.ts`; and
- [ ] `publicApi/near.ts`.

Each consumer must use an authenticated exact tuple, the current validated
method selection, a credential-bound session identity, or an intentional
multi-record result. Signing, export, funding, refresh, and management functions
cannot accept wallet identity alone.

Remove exact-first/V1 fallback from:

- [ ] `login.ts`;
- [ ] `walletIframe/shared/exactSessionState.ts`;
- [ ] wallet iframe host auth handlers;
- [ ] wallet iframe client router handlers; and
- [ ] `BrowserSigningSurface.ts` lock/retirement cleanup.

Primary persistence files:

- `packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.ts`
- `packages/wallet/src/core/signingEngine/session/persistence/walletSessionAuthorizationProjection.ts`

### I9 — Public types, iframe protocol, and vocabulary (B9, B16)

- [ ] Delete `ReusableWalletSessionState` from the SDK domain model.
- [ ] Rename `ReusableWalletSessionMintId` and parser to
      `WalletSessionMintId` and `parseWalletSessionMintId` without an alias.
- [ ] Preserve stored `mint_id` and frozen wire `wallet_session_mint_id` names.
- [ ] Delete reusable-session fields from the public `WalletSession` shape.
- [ ] Delete curve-specific reusable-session signing-surface ports.
- [ ] Delete legacy reusable-session iframe message fields.
- [ ] Bump `WALLET_PROTOCOL_VERSION`, add the host version to CONNECT, validate
      before iframe port adoption, and retain host READY validation.
- [ ] Return `WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` for either skew direction.
- [ ] Publish the matching host SDK and upgrade every known embedding
      application with the final iframe release.
- [ ] Inventory every known host-SDK embed and record its coordinated upgrade
      owner before the final iframe deployment.
- [ ] Replace `ActiveWalletSessionV1` plus separately transported credentials
      with the identity-coupled exact browser boundary type.
- [ ] Delete `registration_established_wallet_session_v1`,
      `RegistrationEstablishedSessionTokens`, and `walletSessionTokenForCurve`.
- [ ] Delete `ActiveWalletSession` aliases that do not denote the exact
      projection.
- [ ] Delete wallet-specific JWT marker/decoder code after its last diagnostic
      caller; preserve console-session JWT types.
- [ ] Preserve the frozen Router A/B `reusable_wallet_session` discriminator,
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

- [ ] Retire or replace
      `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`.
- [ ] Update `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs` to
      forbid V1 tables, `not_v2`, V3 client records, and opaque fallback while
      allowing frozen reusable-operation discriminators.
- [ ] Prefer the type fixtures, behavior tests, and closure searches in this
      plan over new source-text guards.
- [ ] Update `docs/threshold-ecdsa/ecdsa-threshold-signing.md`.
- [ ] Update `docs/auth-gating-routes.md`.
- [ ] Update `docs/intended-behaviours.md` and registration contracts for
      credential-free lost-response replay.
- [ ] Update R115 recovery contracts only where R103F changes Wallet Session
      representation.
- [ ] Update `packages/wallet/README.md`.
- [ ] Correct R103E, R107, and R109D completion records that imply the final
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
- `0028_r103f_phase1_additive_schema_bridge.sql`; and
- `0029_r103f_phase0_registration_replay_tokens.sql`.

`linked_device_wallet_session_authorizations` and
`linked_device_wallet_session_quotas` were already dropped by immutable `0015`;
R103F adds no second deletion task for them. Migration `0026` rebuilds
`wallet_authorities` and recreates the `0024` trigger, so the additive bridge
migration replaces the post-`0026` definition.

Before creating that bridge migration, determine which persistent environments
applied `0024` and record any old-worker all-null-scope claim exposure window.
The replacement must work both where `0024`/`0026` already ran and where they
appear earlier in the same clean-database migration batch.

At the current checkpoint `0028` and `0029` are landed. The next file number is
allocated only after reconciling landed and pending migrations from concurrent
workstreams and is rechecked after each rebase. Applied files are never renamed
to resolve an allocation race.

R103F adds two logical migration stages plus the bounded Phase 0 adapter schema.
Migration `0029` follows `0028` in immutable history, so R0 applies both additive
files before deploying the adapter-aware worker. Applying `0028` does not enable
the bridge worker or direct V2 response family by itself. The later enforcement
and deletion stage may receive a non-contiguous file number.

### Temporary registration replay adapter migration

Migration `0029` adds the digest-only
`registration_replay_opaque_wallet_session_tokens_v1` boundary. It requires an
active exact V1 parent session and quota, binds authority and auth method, caps
token expiry at five minutes and the parent expiry, and contains no bearer
plaintext. New-worker readiness manifests require it. Auth-method cleanup,
hosted redemption cleanup, identity resolution, and logical parent retirement
cover its rows. The enforcement/deletion migration drops it only after the old-
client adapter is absent from every serving worker and its row count is zero.

### Additive bridge migration

The bridge migration:

- replaces the post-R115 exact-only authorized-operation trigger with a rolling
  boundary that accepts fully scoped V2 rows, temporarily accepts all-null-scope
  V1 rows from old workers, and rejects partial scope;
- adds V2 hosted child-credential and exchange tables;
- adds `linked_device_wallet_session_credential_deliveries_v1` with exact
  composite foreign keys, unique digest/link identities, recipient binding,
  ciphertext, acknowledgement, and cleanup receipt state;
- moves `linked_device_authority_allocations` to migration-owned schema after
  validating any existing runtime-created table;
- preserves valid V2 rows with non-null credential digests;
- classifies null-digest V2 rows as unusable; and
- leaves V1 tables present for the bridge deployment.

The migration and deployment preflight report counts for active V1 sessions,
usable V2 sessions, null-digest V2 rows, ordinary opaque tokens, registration-
replay adapter tokens, pending V1-authorized operations, unconsumed V1 hosted
exchanges, V1-only quotas, tagged rollout receipts, and credential-bearing
completion records.

### Enforcement and deletion migration

This migration runs only after every serving worker is exact-only and the V1
drain gates pass. It:

- aborts when active V1 sessions, registration-replay adapter tokens, pending
  V1-authorized operations, unconsumed V1 hosted exchanges, or tagged rollout
  receipts remain;
- retires null-digest and logically expired duplicate V2 rows;
- aborts when multiple usable credential-bearing rows remain for an exact tuple;
- rebuilds `wallet_session_authorizations_v2` with a required active credential
  digest and installs the exact-tuple partial unique index;
- rebuilds parent and child tables in deferred-foreign-key order and aborts on
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

## Rollout state machine

| Stage | Enter action | Supported state | Exit gate |
| --- | --- | --- | --- |
| R0 — Credential-safe registration | Deploy credential-free receipt writer, parser, and old-client adapter | Existing clients receive a legacy-shaped ephemeral response; completion rows contain no plaintext bearer and adapter digests live only in the bounded dedicated table | Old writer revisions quiesced; historical rows remediated; repeated zero-credential query passes |
| R1 — Storage-tolerant precursor | Publish precursor SDK; deploy and enforce client capability | Direct V2 response persists as V5; future rows are preserved | Final unmarked issuance time recorded; maximum unmarked session lifetime drained or invalidated |
| R2 — Bridge | Apply additive migration and deploy bridge worker | New issuance and operations use V2; boundary compatibility accepts existing V1 state | Representative exact operating path passes; matching host SDK/iframe ready |
| R3 — Final browser and protocol | Publish final SDK, upgrade known embeds, deploy matching iframe, enable V6 | Precursor and final tabs coexist under shared-store rules | No unsupported embed is expected to continue; V6 bootstrap and skew tests pass |
| R4 — Exact-only worker | Quiesce predecessor workers; drain V1 sessions, pending operations, and hosted exchanges; normalize tagged receipts | Only exact TypeScript paths serve traffic | All legacy counters are zero; every serving revision is exact-only |
| R5 — Schema deletion | Apply enforcement/deletion migration | Exact code and schema only | Foreign-key check, duplicate preflight, clean database, and deployed-history database pass |

Hard stops:

- R0 remediation waits until every credential-bearing completion writer is
  quiesced.
- The first V6 production write waits for the R1 storage gate.
- The final iframe waits for the matching SDK and known embed upgrades.
- The exact-only worker waits for tagged receipt normalization and V1 drain.
- The deletion migration waits for the exact-only worker deployment.
- The enforcement/deletion file stays outside any branch consumed by the
  apply-all-pending migration workflow until its drain gate passes.
- Migration preflight aborts on an unmappable credential, unknown remediation
  shape, usable exact-tuple duplicate, or foreign-key-check result.

Completed historical operations may replay without a source-activity lookup.
Pending old-worker rows use the temporary all-null-scope persistence branch until
R4. The bridge never projects a V1 bearer into a V2 credential.

## Implementation phases

### Phase 0 — Secure registration persistence

- [x] Introduce `PendingWalletRegistrationCommitV1` and the credential-free
      committed installation projection.
- [x] Replace both registration completion journals with
      `WalletRegistrationSessionCommitReceiptV2`.
- [ ] Deploy the writer, parser, and bounded old-client adapter together.
- [x] Update registration replay from byte-identical bearer output to stable
      fingerprint and committed-projection identity.
- [ ] Quiesce old writers and run the bounded historical remediation.
- [ ] Prove repeated zero-credential counts and record backup/time-travel
      disposition.

Exit: no active writer persists Wallet Session credentials, historical active
rows are remediated, and a current registration path still reaches immediate
signing.

### Phase 1 — Land the exact issuer and one vertical path

- [x] Apply the additive bridge migration to clean and deployed-history
      databases.
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

- [ ] Convert remaining registration, unlock, refresh, sync, ECDSA activation,
      linked activation, and post-recovery login issuers.
- [ ] Make the V2 credential reader required and delete `not_v2` from exact core
      admission.
- [ ] Convert signing, pool fill, signing-session seal, execution-lane
      preflight, recovery warm bootstrap, and operation step-up.
- [ ] Convert status, quota, source activity, authorized-operation replay, and
      typed lifecycle handling.
- [ ] Convert method and authority revocation plus same-method replacement to
      atomic exact retirement.
- [ ] Convert every route in the route policy matrix.
- [ ] Implement hosted child credentials and exact parent lifecycle handling.
- [ ] Update material promotion and exact status readback.

Exit: every new server session is direct V2, and core server services receive
only exact admission contexts. Temporary V1 support exists solely at the bridge
request and persistence boundaries.

### Phase 3 — Convert browser, SDK, recovery, and device linking

- [ ] Implement the storage-tolerant precursor and client capability on every
      issuance boundary.
- [ ] Define the V6 builder/parser and make `replaceExactActive` the only active
      install API.
- [ ] Delete V3 writers and curve-token selection; convert V4/V5 response
      normalization to V6 after the storage gate.
- [ ] Replace wallet-wide active-session reads with an exact selected tuple,
      credential-bound identity, or intentional multi-record result. Let type
      errors and the closure search enumerate remaining callers.
- [ ] Quarantine V3/V4/V5 rows during bootstrap and install while preserving
      future versions and unrelated stores.
- [ ] Complete the recipient-bound linked delivery and acknowledgement state
      machine, including local pending prerequisites and recipient-loss recovery.
- [ ] Close the post-promotion recovery crash window with resumable local
      continuity and normal exact login.
- [ ] Reconcile all affected browser records after material promotion.
- [ ] Bump the host/iframe protocol and remove reusable-session message fields.
- [ ] Rename `ReusableWalletSessionMintId` to `WalletSessionMintId` without an
      alias; preserve stored and frozen wire field names.

Exit: the final client reads and writes only V6 active records, supported mixed
versions reach terminal UI states, and device-link/recovery interruption paths
resume without creating a second authority or ceremony.

### Phase 4 — Deploy, drain, and delete V1

- [ ] Record the maximum lifetime of V1 sessions, ordinary and registration-
      replay adapter tokens, hosted exchanges, pending operation claims,
      response replay, capability-tagged receipts, and acknowledgement cleanup
      receipts. Any unbounded lifetime requires an explicit normalization or
      invalidation gate.
- [ ] Execute rollout stages R1 through R4 and record each zero-state gate.
- [ ] Delete the registration adapter when `already_committed` owns terminal
      replay.
- [ ] Normalize every tagged durable receipt, then delete the temporary client
      capability and parser.
- [ ] Delete the bridge V1 request and persistence resolvers after session,
      operation, and hosted-exchange drains reach zero.
- [ ] Deploy the exact-only worker and confirm every serving revision.
- [ ] Apply the enforcement/deletion migration and update table manifests.
- [ ] Delete remaining V1 stores, ports, services, parsers, types, browser
      records, fixtures, guards, and obsolete documentation.
- [ ] Review extracted modules for forwarding-only wrappers, cycles, duplicate
      validators, compatibility re-exports, and single-caller helpers; inline or
      delete them unless they preserve a clear domain boundary.
- [ ] Run the closure ledger and focused acceptance matrix.

Exit: production code and schema contain only the exact Wallet Session model.

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
- [ ] Rerun `tests/unit/authMenuPasskeyContinuation.unit.test.ts` before using it
      as evidence. Earlier evidence was 13 of 17. Classify the account-sync
      wallet-ID expectation, the Email target callback-publication fixture, and
      the two invalid Google OTP flow-ID fixtures. Update or delete stale
      fixtures; do not add a production compatibility branch for them.
- [ ] Repair the three stale flat-`provenanceKind` fixtures in
      `tests/unit/walletRecoverySourceSelection.unit.test.ts` through the shared
      active-authority builder. Production reads `authority.provenance.kind`;
      the comparator remains strict.
- [ ] Repair the inline envelope-store stub in
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

- [ ] `tests/unit/d1AuthorizationCore.unit.test.ts`
- [x] `tests/unit/d1OwnerProofWalletSessionIssuance.unit.test.ts`
- [x] `tests/unit/d1WalletAuthMethodStore.unit.test.ts`
- [ ] `tests/unit/d1WalletSessionAuthMethodProvenance.unit.test.ts`
- [ ] `tests/unit/linkedDeviceManagement.unit.test.ts`
- [ ] `tests/unit/walletSessionAuthorizationStatus.unit.test.ts`
- [ ] `tests/unit/walletSessionExpiry.boundaryAndServer.unit.test.ts`
- [ ] `tests/unit/registrationEstablishedWalletSessionProjection.unit.test.ts`
- [ ] `tests/unit/syncAccount.yaoOrchestration.unit.test.ts`
- [ ] `tests/unit/routerAbEd25519YaoRecoveryWalletSessionAuthorization.unit.test.ts`
- [ ] `tests/unit/walletExecutionAdmissionV2.unit.test.ts`
- [ ] `tests/unit/walletExecutionLanePreflight.unit.test.ts`
- [ ] `tests/unit/ecdsaV2PoolFillAdmission.unit.test.ts`
- [ ] `tests/unit/syncAccountYaoEnrichment.domain.guard.unit.test.ts`
- [ ] `tests/unit/nearPublicApi.walletSessionAuthorization.unit.test.ts`
- [ ] `tests/unit/walletHostOwnerAuthority.unit.test.ts`
- [ ] `tests/unit/walletSessionOperationCredential.unit.test.ts`
- [ ] `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts`
- [ ] `tests/unit/relayWalletRegistration.boundary.unit.test.ts`
- [ ] `tests/unit/ed25519YaoSealedRefreshPersistence.unit.test.ts`
- [ ] `tests/unit/d1LinkedDeviceAuthorityInstallService.unit.test.ts`
- [ ] `tests/unit/deviceLinkingRoutes.unit.test.ts`
- [ ] `tests/unit/linkDeviceAuthorityResume.unit.test.ts`
- [ ] `tests/unit/authMenuPasskeyContinuation.unit.test.ts`, preserving the
      terminal retry state when the other device cancels
- [ ] `tests/unit/emailOtpEcdsaSigningRefreshRuntimeScope.unit.test.ts`
- [ ] `tests/unit/passkeyEd25519YaoWarmRecovery.unit.test.ts`
- [ ] `tests/unit/walletRecoverySourceSelection.unit.test.ts`, preserving
      eligibility, registration-authority preference, target-family preference,
      and deterministic creation-time/method-ID tie-breaking
- [ ] `tests/unit/walletRecoveryFinalization.unit.test.ts`, preserving additive
      replay and existing continuity authority, method, envelope, and session
- [ ] `tests/unit/walletRecoveryFinalizeWire.unit.test.ts`, preserving strict
      active-authority/active-method projections and cross-wallet rejection
- [ ] `tests/unit/walletRecoveryGoogleEmailOtpFinalizeRoute.unit.test.ts`,
      preserving strict Email recovery projection and server-owned enrollment
- [ ] `tests/unit/walletRecoveryLocalProjection.unit.test.ts`, covering
      interruption and reload across local publication boundaries
- [ ] `tests/unit/authMenuRecoveryContinuation.unit.test.ts`, preserving
      automatic continuation, target-ready retry, and non-cancellable
      finalization
- [ ] `tests/unit/passkeyCustodyRouteService.unit.test.ts`, proving promotion
      replay returns the same server-read committed authority/method projection
- [ ] `tests/unit/scanDevice.firstEmail.unit.test.ts` when linking orchestration
      changes, preserving first-Email routing and release of the iframe
      foreground surface while Device 1 waits
- [ ] `tests/unit/qrCodeScanner.progress.unit.test.ts` when scanner/progress UI
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
- [ ] `tests/e2e/intended-behaviours/auth-method-addition.matrix.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/passkey.add-email-otp.contract.test.ts`
- [ ] `tests/e2e/intended-behaviours/email-otp.add-passkey.contract.test.ts`
- [ ] `tests/e2e/linked-device.operating-path.test.ts` for all four genuine
      source/target factor combinations

#### Required targeted additions and updates

- [x] Direct-V2 atomic issuance failure and replay tests.
- [x] Registration receipt tests proving activation and deferred provisioning
      persist no bearer, child credential, or credential-bearing response.
- [ ] Registration remediation tests for both prefixes: known-shape rewrite or
      deletion, unrelated-row preservation, mapped-bearer retirement,
      unknown/unmappable abort, old-writer quiescence, and repeated zero count.
- [x] Compatibility-adapter test proving stable fingerprint/projection with an
      in-memory V1 bearer whose bytes may differ; delete the test with the
      adapter.
- [x] Adapter-table tests proving identical retries remain usable despite
      response reordering, conflicting replay fails closed, adapter expiry does
      not retire the parent session, parent retirement and method cleanup reject
      adapter tokens, and no plaintext enters durable storage.
- [x] Contract update proving Route 3, service comments, and staging assertions
      no longer promise byte-identical credential-bearing replay.
- [ ] `already_committed` replay test proving no credential fabrication and
      successor exact unlock retirement.
- [ ] Lost founding-registration response contracts for Passkey and Email OTP
      across page or worker termination.
- [x] Mint tests proving same-mint identity replay and fresh-mint replacement.
- [ ] Exact material-resolution tests covering every legacy opaque runtime
      field and rejecting synthesized identities.
- [ ] Linked activation tests proving digest, credential, recipient, ciphertext,
      and session stability on replay.
- [ ] Linked loss tests for response loss, failed exact-record write, recipient
      loss, delivery expiry, acknowledgement loss, and acknowledged cleanup.
- [ ] Linked recipient/AAD binding and cross-session stale acknowledgement
      tests.
- [ ] Crash injection after delivery tombstone, ciphertext removal, allocation
      deletion, link-session deletion, and cleanup completion.
- [ ] Route test proving acknowledgement after live-session deletion
      authenticates through the cleanup receipt and avoids early `not_found`.
- [ ] Local prerequisite transaction tests covering crash atomicity,
      invisibility, receipt replay, both retryable pending reasons, and terminal
      cleanup that preserves pre-existing records.
- [ ] Migration-owned linked-install schema parity test after runtime DDL
      deletion.
- [ ] Exact-record type/parser fixtures for required fields and
      session/credential coupling.
- [ ] `replaceExactActive` test covering same-method retirement, sibling
      preservation, and late V3/V4/V5 writes.
- [ ] Exact-reader tests with two active sibling methods across signing, export,
      funding, refresh, management, readiness, and source claims.
- [ ] Bootstrap quarantine test for a legacy row written after initial cleanup
      by an already-open old tab.
- [ ] Shared-IndexedDB skew tests for future-row preservation, terminal
      `upgrade_required`, late precursor writes, and final-reader containment.
- [ ] Issuance-gate test proving an unmarked client cannot mint, refresh, or
      replace after the drain clock begins.
- [ ] Direct-response precursor matrix covering every issuance boundary,
      response-family replay, V5 normalization, and missing/changed capability.
- [ ] Rollout-receipt normalization test covering known tags, unknown-tag abort,
      credential-free output, and zero final count.
- [ ] Typed lifecycle tests for missing, expired, exhausted, retired,
      method-revoked, authority-revoked, and capability-unavailable results.
- [ ] Authorized-operation full-scope claim and exact replay tests.
- [ ] Hosted nominal-type, disjoint-prefix, issue/redeem/use Origin,
      iframe-parent Origin, authoritative wallet-origin, quota, parent lifecycle,
      and primary-preservation tests.
- [ ] Authority/material-promotion tests covering stable identities, all
      affected server snapshots, all same-authority browser records, and lost
      response readback.
- [ ] Host/iframe protocol-skew tests in both directions with removed fields
      rejected.
- [ ] Targeted IndexedDB cleanup test proving unrelated stores survive.
- [ ] Wallet-bootstrap test covering empty, exact, legacy, malformed, and future
      storage without a blank shell.
- [ ] Exact method- and authority-revocation transaction tests.
- [ ] Additive recovery tests for both targets and source inventories, strict
      committed projections, interruption after promotion, local publication,
      preservation of existing access paths, and one normal exact login.
- [ ] Rolling-deploy migration tests for old-worker all-null scope, fully scoped
      V2, partial-scope rejection, and pending V1 replay.
- [x] Clean-database and deployed-history migration tests covering abort on
      usable duplicates, deterministic retirement of unusable/expired rows, and
      zero foreign-key-check results.
- [ ] Update Router A/B Wallet Session claim fixture helpers.
- [ ] Delete stale inline JWT-shaped Wallet Session fixtures found by closure
      searches.

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
| Shared IndexedDB | Precursor preserves future rows; final reader contains late V3/V4/V5 writes; empty, exact, legacy, malformed, and future states reach explicit UI |
| SDK/iframe protocol | Old/new skew fails in both directions before port adoption or readiness |
| Migration | Clean and deployed-history databases pass; usable duplicates and foreign-key results abort deletion |
| Closure | Every boundary matrix row is final, every temporary path has crossed its removal gate, and all legacy searches are clean |

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

Database closure requires:

- zero active V1 sessions, ordinary opaque tokens, and registration-replay
  adapter tokens;
- zero pending V1-authorized operations;
- zero unconsumed V1 hosted exchanges;
- zero active null-digest V2 sessions;
- zero tagged rollout receipts;
- zero credential-bearing completion records;
- zero usable exact-tuple duplicates;
- zero foreign-key-check results; and
- absence of V1 tables, triggers, views, and aliases after enforcement.

R103F is complete when every boundary-matrix row is in its final state, every
temporary compatibility path has been deleted at its named gate, the acceptance
matrix passes, and the code and database closure ledgers are clean.

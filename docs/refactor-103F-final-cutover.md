# Refactor 103F — Exact Wallet Session Final Cutover

Date created: August 26, 2026

Status: implementation plan. This plan closes the incomplete Wallet Session
cutover left by R103E. No phase is complete until its production paths and
deletion ledger are reconciled against the landed tree.

Design safety audit incorporated: August 26, 2026.

Claude critique and repeated working-tree reconciliation incorporated through
commit `d676e7d22` on August 27, 2026.

## Goal

Make one exact Wallet Session model the only wallet-operation session model
across the server, SDK, iframe, IndexedDB, device linking, signing, export,
administration, recovery, and hosted-wallet handoff.

The final model is:

```text
owner proof
  -> exact active wallet authority
  -> exact active auth method
  -> exact server authorization (`WalletSessionAuthorizationV2`)
  -> one primary opaque operation credential
  -> identity-coupled exact browser record (`record_version: 6`)
  -> operation admission against the exact server authorization
```

Hosted-wallet handoff may mint a short-lived, origin-bound child credential.
That credential resolves to the same V2 authorization and never replaces or
rotates the primary credential.

Delete the parallel V1 implementation:

- `reusable_wallet_sessions`;
- `opaque_wallet_session_tokens`;
- credential-bearing registration completion responses in the shared D1
  side-effect journal;
- reusable-session-to-V2 projection;
- curve-specific client V3 Wallet Session records;
- `not_v2` admission and every runtime fallback to an opaque V1 token;
- V1-only status, revocation, quota, replay, and source-activity checks; and
- fixtures, guards, types, comments, and docs whose only purpose is the retired
  behavior.

The operation credential remains opaque to the browser. Its persisted digest
identifies one exact server authorization. Opaque transport is a security
property, not a compatibility path.

### Boundary-local version labels

R103F has no combined “V2/V6 protocol.” Version labels belong to their own
persistence or wire histories:

- `WalletSessionAuthorizationV2` is the concrete server authorization type and
  D1 record family introduced by R103E;
- `record_version: 6` is the next browser IndexedDB record after the existing
  V3, V4, and V5 client shapes;
- `WalletSessionOperationCredentialV1` is the first version of the opaque
  credential encoding;
- `PendingWalletRegistrationCommitV1` and
  `WalletRegistrationSessionCommitReceiptV2` independently version the local
  pending-registration and server completion-journal schemas; and
- `WALLET_PROTOCOL_VERSION` independently versions the host-SDK/iframe message
  boundary.

Normal prose in this plan uses **exact server authorization**, **exact browser
record**, and **exact Wallet Session model**. The versioned names appear only
when a concrete type, stored record, parser, migration, or compatibility check
requires them. Renaming one boundary to match another would erase its real
history and make migration claims ambiguous.

## Why R103F Exists

R103E introduced `wallet_session_authorizations_v2` while deliberately retaining
`reusable_wallet_sessions` as the V1 boundary during consumer migration. The
opening comment in `0016_r103e_wallet_session_authorizations_v2.sql` records that
staging decision.

The migration was never finished. Current flows commonly:

1. issue a V1 reusable Wallet Session;
2. project it into V2;
3. issue a V2 operation credential after committing the session;
4. persist both a curve-specific V3 client record and an exact V4/V5 record;
5. try exact V2 admission; and
6. fall back to a V1 opaque token when V2 resolution is unavailable.

This produces two authorities for one decision. It has already caused runtime
failures where an exact V2 session reached a V1-only quota or trigger check.
Authority digests and exact method identities are sound only when every reader
consults the same record family.

R103F completes the cutover. It creates no third session abstraction.

## Dependencies and Non-Goals

R103F depends on:

- R107's opaque, server-resolved Wallet Session model;
- R103E's exact authority, auth-method, capability-subject, quota, and operation
  credential records;
- R109C's multiple auth methods and method-bound custody; and
- R109D's exact ordinary Wallet Session for linked authorities.

R103F does not:

- change Passkey, Email OTP, WebAuthn, custody, or MPC cryptography;
- change Wallet Session product lifetime or budget policy;
- merge Wallet Sessions with application or console authentication;
- change the public signer identity, lane, material activation, or key export
  policy;
- rewrite an applied D1 migration; or
- preserve V1 behavior in core functions after replacement.

R115 additive multi-auth recovery is a separate follow-on. The landed current
recovery policy selects the oldest active Passkey for the requested RP, using
auth-method ID as the stable tie-breaker. It replaces only that selected method,
retires its custody envelope and Wallet Sessions, and preserves sibling methods.
R103F preserves this policy while moving its Wallet Session reads and revocation
checks to the exact model. Recovery finalization creates no Wallet Session; its
later normal sign-in must use the direct exact issuer established here. R115
later changes the policy again by preserving the selected source method and its
sessions as well.

The R115 implementation plan landed after this plan. It adds a future
`wallet_recovery` authority-provenance migration that rebuilds
`wallet_authorities`. Serialize that migration after both R103F migration stages
and design it against the post-R103F foreign-key graph. It must not interleave
between R103F's corrective/additive bridge and enforcement/deletion migrations.
If the workstreams overlap, R115 finalization continues to create no Wallet
Session, and its post-finalization login cannot land before R103F's direct exact
issuer. Count the planned R115 migration during number allocation even before a
draft file exists.

Console/dashboard JWTs are a separate authentication system and remain.
Pre-V3 custody-envelope decoding remains isolated at its existing persistence
boundary. Neither belongs to this cutover.

## Preparatory code shaping

The current R103F surface includes several large production files. At the
August 27 working-tree checkpoint, the most relevant are:

| File | Lines | R103F seam |
| --- | ---: | --- |
| `packages/wallet/src/SeamsWeb/operations/auth/login.ts` | 7,907 | exact-method unlock and local discovery |
| `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts` | 6,684 | exact browser-record readers and replacement |
| `packages/wallet/src/core/indexedDB/seamsWalletDB/repositories.ts` | 5,666 | linked local-install transaction |
| `packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationService.ts` | 5,557 | direct issuance and registration replay |
| `packages/wallet/src/SeamsWeb/operations/registration/registration.ts` | 4,667 | pending registration commit and terminal persistence |
| `packages/wallet/src/core/rpcClients/relayer/walletRegistration.ts` | 4,010 | terminal registration response boundary |
| `packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts` | 4,633 | exact operation admission |
| `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts` | 3,608 | exact ECDSA session issuance/admission |

R103F begins with a bounded liveness and code-shaping pass at the seams it will
change. It does not run a repository-wide “split every large file” campaign.
File size alone does not establish a module boundary, and broad movement would
create review noise and collide with concurrent R109D work. The pass deletes
proved dead or obsolete code before moving any surviving code; it never creates
new modules for paths the final exact model removes.

Use these rules:

1. Record the baseline before deleting or moving code. Build a liveness ledger
   for each target file that classifies top-level exports and major internal
   paths as `live_r103f`, `live_unrelated`, `rollout_boundary`, or
   `obsolete_or_unreachable`.
2. Prove `obsolete_or_unreachable` with at least two agreeing evidence sources:
   TypeScript/compiler or lint reachability, import/export search, route or
   assembly registration, production call graph, and the authoritative behavior
   inventory. Dynamic lookup, worker messages, route manifests, generated
   bindings, and test-only imports count as explicit roots and must be checked.
   Text search alone never authorizes deletion.
3. Delete proved dead exports, unreachable branches, duplicate legacy helpers,
   stale feature-mode forks, and fixtures or guards that exist only for retired
   behavior. Keep a rollout compatibility path classified as
   `rollout_boundary` until its named drain gate; delete it in the same change
   that closes that gate.
4. Make dead-code deletion, behavior-neutral extraction, and intended behavior
   changes separate commits where practical. Classify any failing test before
   editing it and never keep production code alive solely for an obsolete
   fixture or source guard.
5. Move one cohesive live domain section at a time, update imports directly, and
   add no deprecated re-export, duplicate helper, optional lifecycle bag, or
   compatibility alias.
6. Preserve behavior with the narrowest existing test or type check. A split
   that changes a fixture, response, persistence shape, or control flow is no
   longer preparatory work and belongs in its owning implementation phase.
   Client movement also runs the existing runtime-entry bundle check so a split
   cannot silently move server-only code or change a worker entrypoint.
7. Start with the client registration terminal-commit seam: pending local
   commit construction, credential-free committed projection parsing, local
   promotion, and session persistence move out of `registration.ts`; the public
   registration orchestration entrypoints remain there.
8. Next isolate the server registration session issuer and credential-free commit
   receipt from `d1WalletRegistrationService.ts`, then isolate the corresponding
   terminal response parser from `walletRegistration.ts`. Keep the side-effect
   boundary generic only where it no longer accepts a public response type.
9. Extract linked local-install and acknowledgement state-machine code when
   Phases 1 and 5 first change those paths. Extract exact-session reader logic
   from `login.ts` and `BrowserSigningSurface.ts` as their callers are converted,
   rather than moving unrelated login or signing behavior first.
10. Stop an extraction if it requires touching more than five existing files,
   inventing a new architecture layer, or widening a domain input. Implement
   the owning behavior directly in the existing module and revisit the split
   after the operating path works.

For each file, the ledger also records its public entrypoints, independently live
responsibilities, import fan-in/fan-out, duplicated validators or builders,
legacy lifecycle branches, and the narrow verification that reaches each retained
responsibility. Mark large cohesive code as live; size alone never becomes a
deletion claim. Mark a live section as extraction-worthy only when it has its own
domain input/output boundary and can move without a forwarding compatibility
wrapper.

The liveness ledger reports lines deleted, lines moved, and net live production
lines separately. The goal is smaller review and context units around R103F
transactions. Line count reduction is evidence of simplification only when the
operating paths and exact invariants remain intact.

## Canonical Domain Model

### Server record

`WalletSessionAuthorizationV2` is the only reusable operation authorization.
It is the digest-free authorization snapshot shared by server domain code and
the client response. Every active snapshot requires:

- tenant and principal identity;
- wallet ID;
- exact authority ID;
- exact auth-method ID;
- authority digest and revocation epoch;
- one or more exact capability subjects;
- authorization, mint, Wallet Session, and quota IDs;
- issue and expiry time.

No field above is optional in an active snapshot. The credential digest belongs
only to the server persistence aggregate:

```ts
type PersistedActiveWalletSessionAuthorizationV2 = {
  readonly kind: 'persisted_active_wallet_session_authorization_v2';
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
  readonly primaryOperationCredentialDigestB64u: DigestB64u;
  readonly retiredAtMs?: never;
};
```

This aggregate is an internal writer/reader shape; it does not imply that quota
and authorization occupy one SQL row. Browser and wire types cannot contain the
digest. Lifecycle readers use separate exhausted, retired, expired,
authority-unavailable, and method-unavailable branches instead of widening the
active aggregate with optional fields.

The direct issuer prepares the session, quota, and primary credential digest
before any write. All three persist in one D1 batch or in the authority
activation CAS that owns the transition. An active V2 row can never be visible
with a null credential digest.

### Threshold-runtime binding ownership

`WalletSessionAuthorizationV2` does not duplicate threshold-runtime state. A
`sign` or `export_keys` capability subject names one exact
`MpcMaterialActivationRef`. Admission resolves that reference through the
authoritative active signer/material repository before constructing any
Router A/B request:

- Ed25519 resolution supplies the exact threshold session, participant set,
  SigningWorker, runtime-policy scope, export identity, and active capability;
- ECDSA resolution supplies the exact key handle, relayer key, participant set,
  runtime-policy scope, normal-signing state, and material activation; and
- authority, method, capability-subject, and resolved material identities must
  all agree before operation admission succeeds.

Before deleting `opaque_wallet_session_tokens`, inventory every field of
`OpaqueOwnerWalletSessionBinding`, including `thresholdSessionId`,
`participantIds`, `keyManifestDigestB64u`, `relayerKeyId`,
`runtimePolicyScope`, `keyHandle`, and `authorizationSessionId`. Each field must
either come from the exact material resolver or be proved obsolete and deleted
from its consumer. If a required field is absent from the authoritative
material projection, extend that projection before deleting the opaque-token
copy. Never synthesize a threshold-runtime identity from `walletSessionId`,
`authorizationId`, or another unrelated identifier.

### Browser credential

The browser receives:

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

The two credential types are nominally distinct and use disjoint boundary
encodings: `wst_` for the primary and `wsh_` for the hosted child. Their parsers
reject the other prefix. Neither credential contains client-authoritative
claims. The server applies the established operation-credential digest function
and uses the parsed prefix to select one exact record family, then re-resolves
the active authority, auth method, capability subjects, expiry, revocation
epoch, and quota.

For founding registration, unlock, refresh, sync, and recovery, the issuer
generates the plaintext credential before committing its digest and returns it
only after the transaction succeeds.

A replay of a server-issued transition cannot reproduce plaintext from a hash.
Its boundary result is therefore explicit:

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

The replay branch never returns a guessed credential and never rotates the
committed hash. The next fresh exact-method unlock atomically replaces that
session and retires its quota.

A lost founding-registration response follows this same rule, including after a
page reload or worker termination. Before the terminal request, the client
persists one `PendingWalletRegistrationCommitV1` containing the ceremony and
idempotency identities, exact founding method, locally created
credential/factor binding, and sealed local signer/custody material needed to
finish installation. It contains no plaintext Wallet Session credential. The
pending record is invisible to normal wallet discovery until server commitment
is proved.

Replaying the terminal request returns `already_committed` plus a
credential-free committed registration projection. The client validates that
projection against its pending record, atomically promotes the wallet profile,
profile authenticator, founding authority/method, signer material, account
projection, and wallet selection, then runs `unlock_exact_method`. That unlock
installs the successor exact browser record and continues to signing. A missing,
conflicting, or incomplete pending record fails closed into an explicit
registration-recovery state; it never fabricates local discovery state.

The durable registration side-effect journal stores a credential-free
`WalletRegistrationSessionCommitReceiptV2`, never the public response. The
receipt contains the operation fingerprint; committed wallet, authority,
method, mint, authorization, Wallet Session, quota, issue, and expiry
identities; and the exact public signer, account, capability, custody-manifest,
and founding-authority projection required to validate and complete the pending
local installation. It contains no primary or child credential, signer
bootstrap that contains a credential, local secret or sealed local material, or
generic `response: T` field. On first execution, the route assembles the public
`issued` response from the ephemeral issuer result only after the receipt CAS
succeeds. On replay after the final client cutover, it reads the receipt and
returns `already_committed`.

This committed installation projection is one shared artifact. During the
adapter window it rebuilds every non-credential field of the legacy V1 replay
response before the route attaches a fresh in-memory bearer. After the client
cutover, the same projection is the `already_committed` recovery payload that a
pending local commit validates and publishes. Do not introduce a second receipt
shape, projection builder, or follow-up receipt migration for those two uses.

The final exact model never signs a fresh bearer during replay. Phase 0 has one
explicitly bounded request-boundary exception for clients deployed before the
new pending-commit parser: it reconstructs the current credential-free public
projection from the receipt and signs a fresh short-lived V1 bearer in memory.
It never persists that bearer. The adapter is deleted before direct exact
issuance and `already_committed` become the public registration replay
contract.

The adapter intentionally ends the old byte-identical terminal-response rule:
the idempotency key, fingerprint, committed identities, and credential-free
projection remain stable, while freshly signed V1 bearer bytes may differ on
replay. Update the Route 3 contract comment in
`threeRouteRegistrationContracts.ts`, the corresponding registration service
comment, and every byte-identity test in the same compatibility change. Replace
those assertions with stable committed-projection identity plus a valid parsed
legacy response. After the adapter is deleted, replay follows the typed
`already_committed` contract; it never returns cached credential-bearing bytes.

This is also immediate security remediation. Current successful
`wallet-registration-activate:` and `wallet-registration-near-provisioning:`
completion rows in `router_ab_yao_versioned_json_records` contain plaintext V1
bearers and have no expiry. Phase 0 counts both prefixes, deploys the
credential-free receipt writer, parser, and old-client adapter together before
the wider cutover, and redacts or deletes historical credential-bearing
responses after preserving only the minimum operation fingerprint and committed
projection needed for safe replay.
The remediation starts only after deployment proves that no worker revision
capable of writing the old completion shape is serving traffic. It repeats the
zero-count query after the maximum in-flight request window.

Before redaction, the remediation hashes each discovered bearer through the
production digest function and retires the matching opaque session/token record
when it remains usable. A row whose credential cannot be mapped safely aborts
the remediation for operator review. Main-database cleanup does not establish
historical backup deletion: Phase 0 records D1 backup/time-travel retention and
either purges recoverable copies through an approved platform procedure or
keeps the exposure open until every affected bearer lifetime has expired. No
cutover drain may leave those plaintext fields in the active D1 database, and
the security-remediation exit may not claim the bearers are unusable without
the retirement-or-expiry proof.

`mintId` is the idempotency key for one issuance attempt. It is never a policy
identity or a renewable session identity. Replaying the same fully scoped mint
returns the same committed authorization identity, including after that session
retires. Same-method replacement always receives a fresh mint ID. Keep the
historical full-scope `mint_id` uniqueness constraint and reshape the existing
V2-by-mint reader into the direct issuer's replay lookup.

Rename the TypeScript brand and parser to `WalletSessionMintId` and
`parseWalletSessionMintId`; delete `ReusableWalletSessionMintId` and
`parseReusableWalletSessionMintId` without aliases. The persisted `mint_id` and
frozen `wallet_session_mint_id` wire field names remain unchanged.

For linked-device activation, Device 2 creates a dedicated,
signer-family-neutral P-256 ECDH credential-delivery recipient during target
preparation. Its public key is authenticated by the verified link state; its
private handle remains in the target worker through final acknowledgement. Before
Device 2 sends the activation request, it durably persists the wallet profile,
profile authenticator, exact auth-method identity and authenticated factor
material, authority identity, and resumable local signer-material installation
state required by the fail-closed exact-method unlock path in one IndexedDB
`readwrite` transaction. Every published record is branch-typed as
`pending_local_install`; normal wallet discovery and signing ignore it. A local
method that must remain pending until server confirmation has a durable
transition that resume can finalize as active before credential decrypt. A
terminal server rejection atomically removes the pending profile,
authenticator, method, authority, signer material, receipt, and selection only
when none predated this link. A crash or retry resumes the exact pending
transaction by receipt identity. Acknowledgement creates none of these
prerequisites. The landed server install service already distinguishes
`server_worker_activation_pending` from `wallet_session_issuance_pending` under
its `pending_local_install` result. Both remain retryable resume states through
this cutover; neither may trigger terminal local cleanup or a second authority.
The server generates the primary credential with the same secure randomness as
every other issuance path and seals it with a versioned P-256 ECDH/AES-256-GCM
envelope using the production WebCrypto construction already exercised by
`sealEmailOtpFactorSecretForWorker`. The delivery type fixes
`alg: 'p256-ecdh-aes256gcm-v1'`. Canonical AAD binds full tenant scope, link
session, wallet, authority, auth method, authorization, Wallet Session, quota,
credential digest, recipient, issue time, and expiry.

The additive schema creates
`linked_device_wallet_session_credential_deliveries_v1`. The activation CAS
inserts one complete row containing those identities, the recipient binding,
sealed envelope and digest, and expected
`WalletSessionInstallationReceiptDigestV1`. That digest covers one shared,
canonical logical receipt containing `record_version: 6`, exact identities,
and primary credential digest. It never covers raw IndexedDB serialization or
plaintext credential bytes and is only an authenticated consistency assertion;
it is not proof that a browser disk write occurred. No nullable
pre-activation delivery row exists. The server stores no plaintext credential.
Replay returns the same row and exact session identity. Final acknowledgement
names all bound identities, the credential digest, and installation-receipt
digest.

Acknowledgement uses an idempotent cleanup state machine. Its first CAS validates
the exact pending delivery, records the acknowledgement receipt, and removes the
sealed ciphertext. Retryable cleanup then removes the authority allocation,
deletes the active link session, and marks the acknowledgement complete. A crash
after any transition leaves enough receipt state for exact replay to resume
cleanup without restoring or resealing the envelope. The small completion
receipt may be deleted only after the acknowledgement replay window.
Device 2 durably records its pending acknowledgement before sending it and
replays that intent during bootstrap until the server returns cleanup complete.
Delivery tombstoning/ciphertext deletion, allocation removal, live-session
removal, and completion are transitions of this one lifecycle. No separate
sealed-delivery cleanup routine may race or bypass acknowledgement replay.

Deleting the active link session cannot delete the authentication needed to
replay acknowledgement. The route parses the acknowledgement identity and reads
the cleanup receipt before requiring a live link session. While the live session
exists, authentication uses its current Device 2 binding. After deletion, a
bounded tombstoned authentication binding in the cleanup receipt validates the
same Device 2 credential, link session, authority, package-set digest,
authorization, Wallet Session, credential digest, and installation-receipt
digest. It authorizes only acknowledgement cleanup/replay and expires with the
receipt. A missing or conflicting tombstone fails closed. The route never
returns `not_found` before checking an authenticated cleanup receipt.

A target that loses its recipient private handle never asks the server to reseal
the committed credential and does not start a second link. It resumes the
durable local authority installation, discovers the committed active method,
and runs `unlock_exact_method`. That unlock atomically retires the unreachable
    linked-activation session, installs a fresh exact browser record, and continues
    to signing.
The same recovery applies when the sealed delivery expires before
acknowledgement.

Hosted exchange uses a separate `wallet_session_hosted_credentials_v2` child
record containing the parent V2 identity, credential digest, audience origins,
expiry, and lifecycle. The exchange code is single-use. The resulting child
credential remains origin-bound and expires no later than its parent; parent
replacement, retirement, or revocation retires every child. Resolving it
returns the parent's exact admission context. It does not mutate the primary
credential digest or create another quota.

The request-boundary resolver parses the nominal credential type first. Hosted
issue requires the request's actual `Origin` to equal `appOrigin`; redemption
and later child-authorized HTTP calls require actual `Origin` to equal the
stored `walletOrigin`. The server derives the permitted wallet origin from
authenticated tenant deployment metadata or an explicit server-side allowlist;
the request-supplied `walletOrigin` must equal that authoritative value before
the exchange row is created. Comparing a request value only with a row populated
from that same value is insufficient. The request origins must equal the stored
exchange row, and the wallet iframe caches the child only when its adopted parent
`MessageEvent.origin` equals the stored `appOrigin`. After audience and parent
lifecycle validation, the resolver returns one `ExactV2AdmissionContext`. Core
signing and management code never branches on the credential source.

### Material-promotion continuity

Signer or capability promotion keeps the existing session-lifetime policy. The
authority-promotion CAS atomically updates the authority and every non-retired
V2 session snapshot owned by that authority, including authority digest and
capability subjects. It preserves method, authorization, Wallet Session, quota,
mint, credential digest, issue time, and expiry identities. This is a lifecycle
transition on an existing authorization, never fresh issuance.

The client reconciles each affected exact browser projection from the successful
promotion response before publishing the promoted runtime. This includes every
sibling method under the same authority in the same browser. Linked devices have
different authorities and are outside that update set.

The active V2 branch of `/wallet/session/status` becomes the named authenticated
exact-projection read boundary. In addition to lifecycle and quota fields, it
returns the complete digest-free `WalletSessionAuthorizationV2` needed to rebuild
the exact browser record. If a promotion response is lost, or a supported client
bootstraps with an exact browser record whose material snapshot may be stale, the
client reads this exact projection and replaces the browser record only after all
immutable identities and its primary credential still agree. A promotion that
cannot prove this continuity retires the affected server sessions in the same
CAS and requires exact-method unlock.
Stale authority digests or capability subjects must never remain silently
usable.

Primary file:

- `packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence.ts`

### IndexedDB record

The only active browser record is a new exact composite with `record_version: 6`.
Its boundary parser requires:

- wallet, authority, and auth-method identity;
- authorization, Wallet Session, and quota IDs;
- capability subjects;
- authority digest and revocation epoch;
- issue and expiry time; and
- the primary operation credential.

The parser proves that `operationCredential.walletSessionId` equals the record's
`walletSessionId`. The existing object store retains its `wallet_session_id`
keyPath and the exact record stores the actual Wallet Session ID there.
`authorization_id` separately stores the authorization ID. The parser proves
both physical fields agree with the exact browser record. A credential from a
sibling method or a different session makes the entire record invalid at the
persistence boundary.

Changing the object-store keyPath requires a `versionchange`. The current
upgrade function deletes every object store, so an authorization-ID keyPath is
outside this cutover unless a store-scoped upgrade mechanism lands first.

This replaces active V3, V4, and V5 rows. Retired `record_version: 6` records may
remain as exact tombstones when the UI or cleanup path needs them. Curve choice
follows the exact record's capability subjects; no curve-specific bearer bundle
remains.

Installing the exact browser record uses the existing exact replacement behavior,
reshaped around the final record type. In one `readwrite` transaction,
`replaceExactActive` retires every active predecessor for the exact
`(walletId, authorityId, authMethodId)` tuple, then inserts the successor. It
leaves sibling methods and authorities intact.
That same transaction classifies every row it scans: known V3/V4/V5 rows are
quarantined, valid final-version rows participate in exact replacement, malformed
final-version rows are corruption, and a future record version is preserved and
reported as `upgrade_required`. A late legacy write cannot abort the successor
install. Every current-SDK bootstrap also quarantines observed V3/V4/V5 rows,
and every exact-record reader ignores them.

### Shared-IndexedDB release boundary

The host/iframe handshake does not govern tabs that share the same IndexedDB.
R103F therefore ships a storage-tolerant precursor SDK before any production
`record_version: 6` write. That precursor still writes V5, but all store
scans distinguish known legacy rows, current rows, malformed rows, and unknown
future versions. It ignores and preserves future rows, never classifies them as
legacy corruption, never overwrites them, and reaches a terminal
`upgrade_required` UI when its own session is no longer usable.

During the precursor stage, every session-creating, replacing, or refreshing
request carries the temporary request-boundary capability
`walletSessionClientCapability` set to
`'direct_exact_response_future_record_tolerant'`. The value proves two things:
the client parses the direct exact issuer response
`{ session, quota, operationCredential }`, and every Wallet Session store scan
preserves unknown future record versions. The precursor normalizes that response
into the existing V5 pair; the final SDK normalizes the same response into the
exact browser record with `record_version: 6`. The bridge therefore never sends
a browser persistence shape over the wire and never downgrades a direct server
authorization into a V1 bearer.

Normalize this capability once at each request boundary. It is deployment
metadata rather than business-operation identity and stays outside ceremony,
mint, and idempotency fingerprints. The operation receipt records the capability
used for first execution. Exact replay requires the same recorded response
family; a different or missing capability returns a typed protocol mismatch and
never changes the committed response family.

That receipt field is temporary persisted rollout metadata. Before deleting its
request parser, wait the maximum response-replay window, or end support for the
old response family through the approved cutover, then rewrite every durable
capability-tagged receipt to the final credential-free `already_committed`
projection. The rewrite never creates a credential. It aborts on an unknown
capability or response family, records before/after counts, and must reach zero
tagged receipts before the exact-only worker deploys. An unbounded receipt
lifetime therefore requires this explicit terminal normalization; elapsed
session lifetime alone is insufficient.

Enforce the capability on founding registration activation and deferred
provisioning, Passkey unlock, Email OTP unlock, sync bootstrap, budget refresh,
ECDSA post-registration activation, current recovery session issuance, and
linked activation. A route that can conditionally issue includes the capability
in its boundary input even when that request ultimately reuses a session. Keep a
route matrix mapping each public request to its internal direct-issuer call.

Once the capability is enforced, clients without it may use already-issued V1
sessions during the bounded drain but cannot mint, refresh, replace, or replay an
issuance response in a different family. Record the last unmarked issuance time
and wait the maximum V1 session lifetime, or perform the approved invalidation,
before enabling the first `record_version: 6` write. Delete this field and its
parser after the exact-only rollout.

The final SDK handles the other direction: it ignores or quarantines late
V3/V4/V5 writes in every reader and inside `replaceExactActive`. This release
boundary retains the current `wallet_session_id` keyPath and does not bump
`SEAMS_WALLET_DB_VERSION`; the destructive all-store upgrade function remains
out of the cutover path.

Registration, unlock, sync, recovery, and device-link responses may still carry
family-specific signer-runtime bootstrap metadata. Those bootstraps contain no
Wallet Session bearer. One exact browser record authenticates every family owned
by the exact authority, while each bootstrap remains bound to its own material
activation and threshold runtime identity.

### Host SDK and iframe release boundary

The npm-installed host SDK and the deployed wallet iframe are a versioned
request boundary. R103F bumps the existing `WALLET_PROTOCOL_VERSION` and extends
the CONNECT/READY handshake in both directions. CONNECT carries the host SDK
version; the iframe validates it before adopting the transferred port. READY
carries the iframe version as today; the host validates it before marking the
connection complete. A missing or mismatched version receives the stable
`WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` failure. On a bad CONNECT version, the
iframe reports its version through the transferred port, closes that port, and
never adopts it. This lets the current old SDK's existing READY validator fail
with the same mismatch code. Older clients that lack validation still cannot
send a message to an adopted port. The iframe never interprets removed
reusable-session fields as the exact Wallet Session message.

This is a coordinated breaking release. Publish the matching host SDK, upgrade every
known embedding application, and deploy the matching iframe/worker release as
one cutover. Embedding applications that retain an older npm SDK must upgrade;
the worker drain window does not make their postMessage protocol compatible.

### Admission result

Operation admission returns a precise result:

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

There is no `not_v2` branch. Core callers never retry a credential against a
different record family.

The D1 reader returns these lifecycle branches as data. Only malformed rows,
column/JSON disagreement, broken foreign-key identity, and impossible state
combinations throw as corruption. Expiry, exhaustion, retirement, and revoked
authority or method state never become HTTP 500/503 errors.

## Required Invariants

1. Every founding, unlocked, refreshed, linked-device, and current-recovery
   ordinary Wallet Session is issued directly as an exact server authorization.
   Any normal sign-in after a future R115 recovery uses the same direct issuer.
2. Every active exact server authorization has one primary operation-credential
   digest before the response or device-link activation is committed.
3. The plaintext primary credential appears only in issuer memory and at its
   receiving browser boundary. Registration journals store credential-free
   commit receipts, and linked activation transports only a credential sealed
   to Device 2.
4. Operation admission identifies the wallet, authority, auth method, and
   capability subjects exclusively from the resolved exact server record.
5. A sibling method or authority can never satisfy admission for another
   session.
6. Status, budget, revocation, replay, source activity, hosted exchange, and
   management routes resolve the same fully scoped authorization identity.
7. At most one active client and server session exists for each exact
   `(walletId, authorityId, walletAuthMethodId)` tuple. Sibling methods may each
   have an active session. Curve choice follows capability subjects.
8. Same-method replacement, auth-method revocation, and authority revocation
   retire the exact server authorization and its quota in the same D1 transaction
   that changes the owning state. Budget consumption atomically transitions the
   quota to exhausted while retaining enough exact identity for a typed
   `exhausted` result. Expiry is a typed logical state; persisted cleanup may
   follow asynchronously.
9. Fresh step-up remains an operation-bound authorization. It never recreates
   a V1 reusable session.
10. Local wallet lock deletes or retires the exact browser record and disposes its
    runtimes. It does not claim atomic server retirement. Server retirement is
    driven by replacement, exhaustion, revocation, explicit session retirement,
    or expiry.
11. R103F does not change recovery replacement policy. Current recovery
    deterministically selects the oldest active RP-matching Passkey, with
    auth-method ID as tie-breaker; replaces only that selected method; retires
    its envelope and exact Wallet Sessions; and preserves sibling methods and
    their sessions. Recovery replay accepts those active sibling envelopes and
    methods. R115 later owns additive recovery, including preservation of the
    selected source method and its sessions. Neither finalization creates a
    session; normal post-recovery sign-in uses the direct exact issuer.
12. No runtime compatibility branch reads `reusable_wallet_sessions` or
    `opaque_wallet_session_tokens` after the cutover deployment.
13. A hosted child credential is audience-bound, resolves only its exact parent
    authorization, shares that parent's quota, and never rotates the primary
    credential. Parent replacement, retirement, expiry, or revocation makes the
    child unavailable.
14. Applied migration files remain byte-for-byte unchanged.
15. The completed refactor removes more production code than it adds, excluding
    forward SQL, tests, generated artifacts, and documentation.
16. Every supported current or storage-tolerant precursor SDK bootstrap reaches
    a terminal UI state. An empty browser shows registration/sign-in, a valid exact
    record restores its exact wallet, an obsolete or malformed Wallet Session
    row is quarantined without hiding wallets stored in the canonical IndexedDB
    repositories, and a precursor that observes a future row reaches
    `upgrade_required` instead of classifying the database as corrupt.
17. Authority or material promotion updates every affected exact server snapshot
    atomically. Every sibling-method exact browser projection under that authority in
    the browser reconciles before promoted runtimes become active; session,
    quota, mint, and credential identities remain unchanged.
18. Linked credential delivery is replayable only through its original
    recipient binding. The final acknowledgement can consume only the exact
    delivery that produced the installed browser record, and every cleanup transition
    is idempotently resumable.
19. Host SDK and iframe protocol versions match exactly before postMessage
    Wallet Session data crosses the boundary.
20. Durable registration completion records contain no plaintext primary or
    child credential. Historical credential-bearing completion rows are counted
    and redacted or deleted during Phase 0.
21. No production `record_version: 6` row is written until the named precursor
    capability is enforced and every unmarked session-issuance lifetime has
    drained or been explicitly invalidated.
22. Linked recipient loss or delivery expiry recovers through the already
    durable local profile, authenticator, auth method, authority, and signer
    installation state plus exact-method unlock. It never creates a second link
    or reseals the committed credential.
23. Hosted issuance accepts `walletOrigin` only when it equals an authoritative
    server-side tenant deployment origin or allowlisted value.
24. A founding-registration response lost across page or worker termination can
    resume only from a durable pending local commit plus the server's
    credential-free committed projection. Publishing local discovery state is
    one transaction and precedes exact-method unlock.
25. The storage-tolerant precursor parses the direct exact issuer response and
    persists V5. The final SDK consumes the same wire response and persists
    `record_version: 6`; the browser persistence version never becomes a server
    response format.
26. Linked acknowledgement cleanup remains authenticated after active
    link-session deletion through a bounded receipt-owned Device 2 binding that
    authorizes no other operation.
27. Every client operation that requires one active session names or derives an
    exact authority/method selection. Multiple sibling-method sessions are a
    valid state and never become wallet-level corruption.
28. The four linked-device factor combinations use genuine source inventories.
    Passkey-to-Email starts with no Email method or enrollment and exercises the
    first-Email target-enrollment branch; Email-to-Passkey starts with no Passkey
    method. Acceptance never pre-adds the target family to Device 1.

## Transaction Boundaries and Hard Stops

| Transition | One required transaction / CAS |
| --- | --- |
| Registration server completion | credential-free operation receipt; first-response credential remains ephemeral |
| Registration client completion | validate pending registration + atomically publish profile, authenticator, authority, method, signer/account projections, and selection |
| Server-issued session | quota + V2 authorization + primary credential digest |
| Linked activation | authority + auth method + link state + quota + V2 authorization + credential digest + sealed Device 2 delivery |
| Linked local prerequisites | atomically persist pending profile, authenticator, method/factor, authority, signer material, receipt, and selection before server activation |
| Linked acknowledgement | validate and tombstone exact delivery + remove ciphertext, then idempotently resume allocation/session cleanup to a completion receipt |
| Same-method replacement | retire predecessor + close predecessor quota + retire its hosted children + insert successor quota/session/digest |
| Explicit session retirement | retire V2 session + close quota + retire hosted children |
| Auth-method revocation | revoke method + retire its V2 sessions + close their quotas + retire hosted children |
| Authority revocation | revoke authority and owned methods + retire their V2 sessions + close their quotas + retire hosted children |
| Material promotion | replace authority material projection + update every affected non-retired V2 snapshot; preserve session, quota, mint, and credential identities |
| Budget use | authorized-operation claim + exact quota decrement/exhaustion under full V2 scope |
| Exact browser-record install | retire exact same-method predecessor rows + insert final record; preserve siblings |

Stop the phase and correct the design if any implementation would:

- expose an active V2 session before its primary credential digest commits;
- persist a public registration response or any plaintext operation credential in
  a durable side-effect record;
- rotate a direct exact primary credential during replay; the named Phase 0
  in-memory V1 adapter is the only bounded legacy-response exception;
- return `already_committed` for founding registration without a validated
  pending local commit and a credential-free projection sufficient to publish
  every exact-method unlock prerequisite;
- deploy the credential-free registration receipt writer to old clients without
  the V1 replay adapter that preserves their currently parsed terminal shape;
- retain a byte-identical terminal-response claim while the adapter signs a fresh
  V1 bearer for replay;
- change the response family of an already committed issuance because a replay
  supplied a different client capability;
- write a primary credential digest through a separate post-issuance updater;
- accept a credential whose Wallet Session ID does not match the client record;
- construct a hosted child as a primary credential or resolve one through the
  primary table;
- infer an auth method from wallet-wide uniqueness;
- backfill or reinterpret a V1 bearer as a V2 credential;
- synthesize a threshold-runtime identity from a Wallet Session or
  authorization identifier;
- promote signer material while leaving an affected exact server or browser
  projection stale;
- reseal a linked credential to a different recipient after activation;
- restart linking after recipient loss when durable exact-method unlock state is
  available;
- delete the live link session before retaining the bounded authentication state
  required to replay acknowledgement cleanup;
- delete the temporary client-capability parser while any durable receipt still
  carries its rollout tag;
- expose a partially installed Device 2 profile, authenticator, method,
  authority, or signer record to normal discovery;
- enable a `record_version: 6` write before the storage-tolerant precursor
  issuance gate drains;
- use an IndexedDB version upgrade that deletes unrelated stores;
- install an exact browser record without retiring its same-method predecessor;
- let an obsolete or future IndexedDB row abort exact-record replacement or be overwritten
  by a reader that does not own its version;
- accept a hosted `walletOrigin` solely because it matches a row populated from
  the same request value;
- accept Wallet Session postMessage data before the exact iframe protocol
  version handshake succeeds;
- convert an expected expired, exhausted, retired, or revoked state into an
  exception or HTTP 500/503;
- land the deletion migration before the rolling-deploy drain conditions pass;
- choose an arbitrary survivor when multiple usable exact-tuple V2 rows exist;
- treat execution of `PRAGMA foreign_key_check` as success without asserting
  that it returned zero rows; or
- convert a request-boundary route without an explicit row in the policy matrix;
- move an `obsolete_or_unreachable` path into a new module instead of deleting
  it with its liveness evidence; or
- delete a large-file path using text search as its only reachability proof.

## Full Production Inventory

The checkboxes below are the deletion ledger. A checked item means the named
production path has been replaced and deleted, not merely bypassed.

### A. Server V1 persistence and service surface

- [ ] Delete `readReusableWalletSessionStatus` from
      `d1AuthorizationStore.ts`, `authorization/service.ts`, and
      `authServicePort.ts`.
- [ ] Delete `putWalletSessionAuthorization` and its V1 readback helpers.
- [ ] Delete `issueReusableWalletSession` and its preparation/domain inputs.
- [ ] Delete the V1 `readWalletSessionAuthorizationByMint`. Preserve and narrow
      the V2-by-mint replay reader around full scope, exact method, and mint ID.
- [ ] Delete `revokeReusableWalletSessionsForAuthMethod` and its prepared SQL
      statement builder.
- [ ] Delete `putOpaqueWalletSessionToken`.
- [ ] Delete `readOpaqueWalletSessionToken`.
- [ ] Delete `readOpaqueWalletSessionTokenByIdentity`.
- [ ] Delete `issueOpaqueWalletSessionToken` and
      `resolveOpaqueWalletSessionToken` from the service and route port.
- [ ] Delete `ResolvedOpaqueWalletSessionToken`, legacy curve-binding types,
      and pre-provenance runtime branches with those APIs.

Primary files:

- `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`
- `packages/wallet-server/src/authorization/service.ts`
- `packages/wallet-server/src/router/framework/authServicePort.ts`
- `packages/wallet-server/src/authorization/domain.ts`

### B. V1-to-V2 issuance bridge

- [ ] Delete `issueWalletSessionAuthorizationV2FromReusableSession`.
- [ ] Delete `refreshWalletSessionAuthorizationV2FromReusableSession`.
- [ ] Delete `projectReusableWalletSessionV2` and its projection types.
- [ ] Replace separate session and credential writers with one direct issuer
      that prepares `{ session, quota, primaryCredential, credentialDigest }`.
- [ ] Delete `putWalletSessionAuthorizationV2OperationCredential` and
      `issueWalletSessionAuthorizationV2OperationCredential`. No production API
      may update `operation_credential_hash` after session insertion.
- [ ] Persist session, quota, and primary credential digest in one batch or the
      owning authority-activation CAS before returning success.
- [ ] Rebuild the V2 table in a forward migration so every active row requires
      a non-null primary credential digest.
- [ ] Make same-method replacement retire the previous exact V2 session and
      exhaust its quota in the same transaction that installs the new session.
- [ ] Add a partial unique index enforcing at most one non-retired V2 session
      per full scope and exact `(wallet, authority, authMethod)` tuple. The
      issuer retires an expired/exhausted predecessor before inserting its
      replacement.
- [ ] Keep `mint_id` unique across historical V2 rows. Give every replacement a
      fresh mint ID and delete policy-derived mint helpers that cannot identify
      one issuance attempt.
- [ ] Make the V2-by-mint persistence reader accept the narrow replay key and
      return the committed exact identity without requiring the caller to
      reconstruct the entire expected session record.
- [ ] Make server-issued replay return the already committed result without
      rotating its credential. A flow that cannot reproduce the plaintext
      returns an explicit retry/unlock result.
- [ ] Add `PendingWalletRegistrationCommitV1` before the terminal request. Make
      it sufficient to resume after page reload or worker termination while
      keeping it invisible to normal wallet discovery.
- [ ] Change the final founding-registration replay contract from fresh V1
      bearer issuance to `already_committed -> unlock_exact_method`. Validate a
      credential-free committed projection against the pending record,
      atomically publish every local discovery and signer prerequisite, and then
      unlock so a lost response reaches a fresh exact browser record and
      signing.
- [ ] Replace registration activation and deferred NEAR provisioning completion
      records with `WalletRegistrationSessionCommitReceiptV2`. The generic
      side-effect store persists only the credential-free receipt and public
      committed installation projection; the first public response attaches the
      ephemeral issued credential after the receipt CAS, while final-cutover
      replay maps the receipt to `already_committed`.
- [ ] Use that one committed installation projection for both compatibility
      replay and final pending-commit recovery. The adapter may attach only its
      fresh in-memory V1 bearer; add no second receipt/projection shape or
      intermediate receipt migration.
- [ ] Keep one Phase 0 request-boundary adapter for clients without the pending
      commit parser. It reconstructs the current credential-free public
      projection and signs a short-lived V1 bearer only in memory. Delete the
      adapter before enabling the final replay contract and direct exact
      issuance.
- [ ] In the same adapter change, revise the Route 3 contract and service comments
      plus every byte-identical terminal replay assertion. Require a stable
      fingerprint and committed projection with a valid parsed legacy response;
      bearer bytes are deliberately fresh during the adapter window.
- [ ] Make the receipt parser reject `walletSessionToken`, primary or child
      operation credentials, credential-bearing signer bootstraps, and generic
      persisted response payloads.
- [ ] Count, redact, or delete historical credential-bearing rows under both
      registration side-effect prefixes during Phase 0. Preserve only the
      fingerprint and credential-free committed installation projection
      required for replay.
- [ ] Make linked activation generate one primary credential, seal it through
      the dedicated Device 2 credential-delivery recipient, and commit its
      digest and sealed delivery atomically with activation.
- [ ] Preserve material-promotion continuity in
      `d1Ed25519YaoCapabilityPersistence.ts`: update every affected non-retired
      V2 authority digest and capability-subject projection in the authority
      promotion CAS while preserving authorization, session, quota, mint, and
      primary credential identity.
- [ ] Return every same-authority promoted session projection for sibling-method
      exact browser-record reconciliation. Extend the active exact
      `/wallet/session/status` response
      into the authenticated digest-free exact-projection boundary used after a
      lost response and during bootstrap. An unprovable transition atomically
      retires the affected sessions and requires exact-method unlock.

Convert every current bridge caller:

- [ ] founding registration in `d1WalletRegistrationService.ts`;
- [ ] registration session reuse in `d1WalletRegistrationService.ts`;
- [ ] Wallet Session budget refresh in `d1WalletRegistrationService.ts`;
- [ ] linked Ed25519 activation in `d1WalletRegistrationService.ts`;
- [ ] active unlock in `d1RouterApiAuthService.ts`;
- [ ] sync bootstrap in `syncAccountBootstrap.ts`;
- [ ] ECDSA post-registration activation in `thresholdEcdsa.ts`;
- [ ] `mintRouterAbEd25519YaoWalletSessionV1` in
      `routerAbEd25519YaoProductRegistration.ts` and its sync/registration
      callers;
- [ ] `issueRouterAbEd25519OpaqueWalletSessionToken` and every direct caller; and
- [ ] any recovery or device-link installation path found by the final
      zero-reference search.

Additional primary file:

- `packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration.ts`
- `packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoCapabilityPersistence.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary.ts`
- `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService.ts`
- `packages/shared-ts/src/utils/registrationEstablishedSession.ts`

### C. Operation admission fallbacks

- [ ] Make `readWalletSessionAuthorizationV2ByOperationCredential` required in
      `authServicePort.ts`.
- [ ] Delete `WalletSessionOperationCredentialResolution.kind === 'not_v2'`.
- [ ] Remove `resolveOpaqueOwnerWalletSessionAdmission` from core validators.
      Keep it reachable only through the explicitly named bridge
      request-boundary resolver until Phase 6, then delete it.
- [ ] Delete Ed25519 validator fallback to a V1 token.
- [ ] Delete ECDSA validator fallback to a V1 token.
- [ ] Make operation kind required for every reusable-session admission.
- [ ] Delete the `operationKind === null` ECDSA path.
- [ ] Convert operation step-up identity resolution in
      `routerAbPrivateSigningWorker.ts`.
- [ ] Convert signing-session seal authorization in `createFetchRouter.ts`.
- [ ] Convert Ed25519 reuse of an ECDSA V1 session in `thresholdEd25519.ts`.
- [ ] Convert ECDSA pool-fill admission in `thresholdEcdsa.ts`.
- [ ] Convert recovery warm-session authorization in
      `routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`.
- [ ] Resolve the capability subject's exact material activation before building
      either curve's Router A/B request. Replace every opaque-binding field read
      with that resolver output or delete the field's consumer.
- [ ] Reject any path that substitutes a Wallet Session or authorization ID for
      `thresholdSessionId`, `authorizationSessionId`, or another runtime identity.

Primary files:

- `packages/wallet-server/src/router/auth/commonRouterUtils.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEd25519.ts`
- `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts`
- `packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts`
- `packages/wallet-server/src/router/transport/fetch/createFetchRouter.ts`
- `packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`

### D. Status, replay, quota, and source-activity checks

- [ ] Make `/wallet/session/status` resolve only the V2 operation credential.
- [ ] Make its active V2 branch return the full digest-free
      `WalletSessionAuthorizationV2` plus exact quota lifecycle data. Validate
      immutable authorization, Wallet Session, quota, authority, and method
      identities against the credential-bound request before returning it.
- [ ] Use that projection read to reconcile a possibly stale exact browser record
      during bootstrap and after promotion-response loss. A promotion response
      updates every local sibling-method record owned by the same authority before
      any promoted runtime becomes visible.
- [ ] Change the V2 persistence reader to return typed missing, expired,
      exhausted, retired, authority-unavailable, and method-unavailable states.
      Reserve exceptions for corrupt persistence.
- [ ] Make fully scoped `isAuthorizedOperationSourceActive` rows use the V2
      authorization lookup and exact authority/method checks. Retain one
      temporary all-null-scope V1 persistence branch for pending rows written
      by pre-bridge workers, then delete it in Phase 6.
- [ ] Replace every quota lookup through `reusable_wallet_sessions` with the
      V2 authorization's `quota_id`.
- [ ] Bind the existing `linked_scope_org_id`, `linked_scope_project_id`, and
      `linked_scope_env_id` columns on every new authorization-grant operation.
      Reject partially populated scope at the persistence boundary.
- [ ] Replace the V1-only authorized-operation claim trigger with a lookup by
      the complete `(namespace, org, project, env, tenant, authorizationId)`
      V2 key.
- [ ] Ensure replay resolves the same V2 authorization that admitted the first
      execution and rejects scope, method, authority, quota, or capability
      disagreement.
- [ ] Remove V1 status calls from Ed25519 reuse and ECDSA activation.

Primary files:

- `packages/wallet-server/src/router/transport/fetch/routes/sessions.ts`
- `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`
- `packages/wallet-server/migrations/d1-signer/0001_signer_d1_initial.sql`

The applied `0001` file stays unchanged. A new forward migration replaces its
trigger.

The landed tree contains scope bindings, a V2-only source reader, and the
exact-only `0024_r103f_v2_authorized_operation_claim.sql` trigger. That trigger
landed before the rolling-deploy boundary. Treat it as immutable and supersede it
with the additive bridge migration below; do not cite its presence as proof that
the operating cutover is complete.

### E. Revocation, recovery, and custody checks

- [ ] Retire V2 authorizations by exact auth-method ID during auth-method
      revocation.
- [ ] Retire V2 authorizations by exact authority during linked-device
      revocation.
- [ ] Append exact V2 retirement and quota exhaustion statements to the same
      auth-method or authority revocation CAS.
- [ ] Transition a consumed quota to exhausted without traversing the V1 table;
      keep its exact V2 identity readable for typed status and step-up.
- [ ] Replace `hasActiveWalletSessionsForAuthMethod` with a V2 query.
- [ ] Remove duplicate V1 revocation statement builders in
      `d1WalletAuthMethodStore.ts`.
- [ ] Convert the current recovery finalization and replay checks to exact V2
      while preserving deterministic selection of the oldest active
      RP-matching Passkey with auth-method ID as tie-breaker. Retire only that
      selected method's exact sessions and envelope; preserve sibling methods,
      sessions, and envelopes; and accept them during committed replay. R115's
      later preservation of the selected source remains outside this refactor.
- [ ] Keep wallet lock local: retire/delete exact browser records and dispose
      runtimes. Do not claim atomic remote retirement.
- [ ] Return expiry and exhaustion as typed states even when row cleanup is
      deferred.

Primary files:

- `packages/wallet-server/src/core/d1WalletAuthMethodStore.ts`
- `packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore.ts`
- `packages/wallet-server/src/router/domains/passkeyCustody/walletRecoveryFinalization.ts`
- `packages/wallet-server/src/core/deviceLinking/linkedDeviceManagement.ts`

### F. Device-link source and owner authorization

- [ ] Delete `readOpaqueWalletSessionTokenByIdentity` fallback from
      `d1LinkedDeviceVerifiedLinkSourceReader.ts`.
- [ ] Require the exact V2 source session for owner approval.
- [ ] Require the exact operation credential in execution-lane preflight.
- [ ] Confirm post-link installation persists the exact V2 record and operation
      credential before publishing authenticated UI state.
- [ ] Add a dedicated signer-family-neutral P-256 ECDH credential-delivery
      recipient to target preparation and authenticate it through the verified
      link record.
- [ ] Before sending server activation, durably persist the Device 2 wallet
      profile, profile authenticator, exact auth-method/factor state, authority
      identity, and resumable local signer-material installation state required
      by fail-closed `unlock_exact_method` in one IndexedDB `readwrite`
      transaction. Store every new lifecycle record as `pending_local_install`,
      hide it from normal discovery, make replay idempotent by receipt identity,
      and define terminal rejection cleanup that preserves any pre-existing
      local record. Resume finalizes the method as active before credential
      decrypt.
- [ ] Preserve the landed `pending_local_install` reasons
      `server_worker_activation_pending` and `wallet_session_issuance_pending` as
      retryable exact-resume branches. Neither reason may delete pending local
      prerequisites, allocate a second authority, or restart linking.
- [ ] Persist the server-generated primary credential digest and sealed Device
      2 delivery in one complete
      `linked_device_wallet_session_credential_deliveries_v1` row inside the
      authority activation CAS.
- [ ] Give the delivery row exact composite foreign keys to its linked
      installation and V2 authorization, and unique full-scope link-session and
      credential-digest identities.
- [ ] Bind the delivery envelope AAD to full tenant scope, link session, wallet,
      authority, method, authorization, Wallet Session, quota, credential
      digest, recipient, issue time, and expiry. Store the envelope, binding
      digest, and expected `WalletSessionInstallationReceiptDigestV1`; store no
      plaintext. Define the receipt digest over one shared canonical logical
      shape, never raw IndexedDB bytes or plaintext credential bytes.
- [ ] Make activation replay return that same sealed delivery and exact session
      identity. Never mint or overwrite a credential during replay.
- [ ] Retain the sealed delivery across a lost activation response. Consume it
      only after the final local-installation acknowledgement validates, by
      tombstoning the row and removing ciphertext while preserving the bounded
      replay receipt.
- [ ] Order Device 2 as decrypt → validate exact identities → persist the exact
      browser record → activate runtimes → acknowledge. A failure before
      persistence sends no acknowledgement and remains replayable.
- [ ] Extend the final acknowledgement with authorization ID, Wallet Session
      ID, credential digest, and installation-receipt digest. Reject
      cross-session or stale acknowledgement before consuming the delivery.
- [ ] Implement acknowledgement as an idempotent state machine: validate and
      tombstone the exact delivery while removing ciphertext, delete the
      authority allocation, delete the active link session, and record cleanup
      completion. Replay resumes the first incomplete transition and never
      restores the envelope. Keep all four transitions in this one lifecycle;
      delete or fold any parallel sealed-delivery cleanup path that can race it.
- [ ] Retain a bounded Device 2 acknowledgement-authentication tombstone in the
      cleanup receipt. Make the route parse the acknowledgement identity and
      resolve that receipt before requiring a live link session, so replay after
      link-session deletion can authenticate, resume, and report completion.
      The tombstone authorizes only the exact acknowledgement cleanup and
      expires with the receipt.
- [ ] Persist the pending acknowledgement intent locally before sending it.
      Bootstrap replays that exact intent until the server reports cleanup
      complete, then clears it with the local delivery-resume record.
- [ ] On recipient-handle loss or delivery expiry, resume the durable local
      authority installation and run exact-method unlock. Retire the unreachable
      activation session; do not reseal or create another link.
- [ ] Confirm linked-device signing, export availability, account menus, and
      inventory work immediately after linking without a lock/unlock cycle.
- [ ] Preserve the landed cancellation contract across client orchestration:
      local cancellation remains interactive and returns focus to the opener;
      remote cancellation emits one terminal `cancelled` event, releases local
      resources, and leaves the hosted auth menu in an explicit retry state
      rather than a perpetual loading state.
- [ ] Delete `INSTALLATION_SCHEMA_SQL` and the other runtime `CREATE TABLE`
      copies from `d1LinkedDeviceAuthorityInstallService.ts`. Forward migrations
      own these schemas so production and local execution cannot drift.
- [ ] Move `linked_device_authority_allocations` into the additive migration.
      Keep `linked_device_authority_installations` governed by immutable `0018`
      and retain its `target_factor_verified_at_ms >= 0` check; the current
      runtime SQL copy already omits that check and demonstrates the drift this
      deletion closes.

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

### G. Request-boundary routes still backed by V1

These public behaviors remain. Their storage and authorization source changes
to V2.

- [ ] Reback hosted Wallet Session exchange issue and redemption with an
      origin-bound V2 child credential. It resolves the parent V2 session,
      shares its quota, and never rotates the primary credential.
- [ ] Define `HostedWalletSessionOperationCredentialV1` as a nominal type with
      the `wsh_` boundary encoding. Give primary and child credentials separate
      parsers, encodings, tables, and lookup branches.
- [ ] Make hosted exchange curve-free on the wire. Issue accepts
      `{ appOrigin, walletOrigin }`; redemption accepts
      `{ exchangeCode, nonce, appOrigin, walletOrigin }`; success returns the
      parent Wallet Session ID, one
      `HostedWalletSessionOperationCredentialV1`, and its expiry. Delete `curve`
      and `walletSessionToken` from these exact boundary shapes.
- [ ] Preserve the two-leg transport checks: issue requires actual `Origin` to
      equal `appOrigin`; redemption and later child use require actual `Origin`
      to equal `walletOrigin`; every supplied origin must equal the stored
      exchange row.
- [ ] Resolve the permitted `walletOrigin` from authenticated tenant deployment
      metadata or a server-side allowlist during issue. Reject a request value
      that is syntactically valid and self-consistent but is not authoritative
      for that tenant.
- [ ] Cache or use a hosted child in the iframe only when the adopted parent
      `MessageEvent.origin` equals its stored `appOrigin`.
- [ ] Give each hosted row an exact composite foreign key to its V2 parent and a
      unique credential digest. Same-method replacement, explicit retirement,
      method revocation, and authority revocation retire children in their
      owning transaction. Parent expiry makes children logically unavailable;
      cleanup may follow asynchronously.
- [ ] Convert the wallet-iframe hosted-session cache and consumers from a
      per-curve token map to one audience-bound child operation credential.
- [ ] Convert Email factor-release `wallet_session` admission.
- [ ] Convert `/auth/identities` and auth link/unlink admission.
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

Request compatibility is normalized once at these route boundaries. Core
services receive only an exact V2 admission context.

Every converted route declares and tests this policy before its V1 resolver is
deleted:

| Route family | Exact identity | Capability / assurance | Quota |
| --- | --- | --- | --- |
| Session status | credential's exact method and authority | active V2 session | neutral |
| Signing and pool fill | exact method, authority, and material activation | matching `sign` subject | consuming |
| Key export | exact method, authority, and material activation | matching `export_keys` subject plus fresh step-up | neutral |
| Device-link approval/preflight | exact source method and authority | `link_devices`; existing owner assurance | neutral |
| Device revocation | exact owner method and target authority | `revoke_devices`; required fresh proof | neutral |
| Email factor release | exact Email method and enrollment | matching Ed25519 subject and one-time proof | neutral |
| NEAR funding | exact method and Ed25519 activation | matching `sign` subject | neutral |
| Public-key/authenticator inventory | exact method and authority | retain current read policy | neutral |
| Auth identity link/unlink | exact method and authority | retain current fresh-step-up policy | neutral |
| Custody ownership upgrade | exact method equals envelope owner | current custody proof | neutral |
| Hosted exchange | parent exact method and authority | issue app Origin + redeem/use wallet Origin + iframe parent Origin; audience-bound child credential | parent quota policy |

No route may infer an auth method from wallet-wide uniqueness or accept a
sibling credential because it belongs to the same wallet.

Device-link approval obtains the exact source method from the currently
authenticated V2 credential. Scanning a QR code does not add a Device 1 method
chooser.

### H. Retire legacy client persistence and install the exact browser record

- [ ] Delete `WALLET_SESSION_AUTHORIZATION_RECORD_VERSION` for V3.
- [ ] Delete `ActiveWalletSessionAuthorizationProjection` and its retired V3
      sibling.
- [ ] Delete `WalletSessionAuthorizationTokenBundle`.
- [ ] Delete curve token extractors and curve ID extractors.
- [ ] Delete V3 builders, parsers, row serializers, merges, and retirement
      helpers.
- [ ] Delete `replaceActive`, `createOrMergeExactActive`, and
      `upsertActiveWithCurveMerge` where they operate on V3 projections.
- [ ] Delete `readActiveForWallet`, which deliberately excludes V4/V5 rows.
- [ ] Delete `persistActiveWalletSessionAuthorizationCurve`.
- [ ] Delete `persistActiveWalletSessionAuthorizationFromRegistration`.
- [ ] Delete the V3 ECDSA bootstrap projection.
- [ ] Define one branch-specific builder and one strict parser for the exact
      `record_version: 6` composite. Require `authorizationId`, `walletSessionId`,
      `quotaId`, exact method/authority identity, subjects, and the primary
      credential.
- [ ] Reject the exact browser record unless the credential's Wallet Session ID
      equals the record's Wallet Session ID.
- [ ] Retain the existing `wallet_session_id` keyPath and store the exact record's
      `walletSessionId` there. Store `authorizationId` separately under
      `authorization_id` and cross-check both fields in the boundary parser.
- [ ] Reshape `replaceExactActive` around the exact browser record and make it the
      only active install API. Its single `readwrite` transaction retires active predecessors for
      the exact wallet/authority/method tuple before inserting the successor;
      sibling methods and authorities remain unchanged. The same scan
      quarantines known V3/V4/V5 rows, rejects a malformed final record, preserves unknown
      future versions, and never lets a late legacy row abort installation.
- [ ] Rename remaining repository APIs around exact-record behavior only after the
      duplicate APIs are removed.
- [ ] Remove active V3, V4, and V5 rows with a targeted transaction against the
      existing Wallet Session store. Preserve every unrelated IndexedDB store.
- [ ] Run that targeted quarantine during every current-SDK bootstrap and make
      all exact-record readers ignore obsolete rows. This contains writes from old tabs
      that were already open during the cutover.
- [ ] Before any `record_version: 6` production write, publish a storage-tolerant precursor SDK.
      Its readers preserve and ignore unknown future record versions, never
      classify them as legacy corruption, and surface `upgrade_required` when
      their own usable session is unavailable.
- [ ] Add the temporary request-boundary capability
      `walletSessionClientCapability` set to
      `'direct_exact_response_future_record_tolerant'` on every route in the
      issuance matrix. Prove the precursor parses the direct exact issuer
      response into V5 and preserves future rows. Record the capability in the
      operation receipt, reject response-family changes on replay, drain or
      invalidate the final unmarked session lifetime before enabling
      `record_version: 6`, and delete the capability after the exact-only
      deployment.
- [ ] Do not bump `SEAMS_WALLET_DB_VERSION` while the current upgrade function
      deletes all object stores. A general in-place migration framework is
      outside this cutover.

Primary files:

- `packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.ts`
- `packages/wallet/src/core/signingEngine/session/persistence/walletSessionAuthorizationProjection.ts`

### I. Client V3 readers and fallback consumers

Convert every reader and legacy writer to the exact browser record:

- [ ] `BrowserSigningSurface.ts`;
- [ ] `login.ts`;
- [ ] `registration.ts` legacy registration writer;
- [ ] `syncAccount.ts` legacy recovery/sync writer;
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

The post-`03b39d34f` August 27 checkpoint contains 40
`readActiveForWallet` call sites across 18 production consumer files.
`registration.ts` and recovery `syncAccount.ts` remain in the inventory as
legacy writers and are outside that reader count. Before replacing the
repository API, give every reader call site one explicit selection source:

- an already authenticated `(walletId, authorityId, authMethodId)` tuple;
- the current wallet selection's exact active method, revalidated against its
  authority;
- a credential-bound exact session identity; or
- a list/readiness operation that intentionally returns every active exact
  record and handles zero, one, or many without treating sibling methods as
  corruption.

- [ ] Record that selection source beside every call site in the conversion
      ledger. A function that performs signing, export, funding, refresh, or
      management may not accept only `walletId` when multiple methods can be
      active.
- [ ] Add a zero-reference check for `readActiveForWallet` and a sibling-method
      test proving each converted caller uses the selected exact method, never
      insertion order or wallet-wide uniqueness.

Remove exact-first-then-reusable fallback logic from:

- [ ] `login.ts`;
- [ ] `walletIframe/shared/exactSessionState.ts`;
- [ ] wallet iframe host auth handlers;
- [ ] wallet iframe client router handlers; and
- [ ] `BrowserSigningSurface.ts` lock/retirement cleanup.

### J. Public and shared legacy types

- [ ] Delete `ReusableWalletSessionState` from the SDK domain model.
- [ ] Rename `ReusableWalletSessionMintId` and its parser to
      `WalletSessionMintId` and `parseWalletSessionMintId` across production,
      generated bindings, fixtures, and type checks. Add no compatibility
      alias; preserve the stored and wire field names.
- [ ] Delete reusable-session fields from the public `WalletSession` shape.
- [ ] Delete curve-specific reusable-session signing-surface ports.
- [ ] Delete legacy reusable-session iframe message fields.
- [ ] Bump `WALLET_PROTOCOL_VERSION` for the exact Wallet Session message contract. Put that
      version in CONNECT, reject it in the iframe before port adoption when it
      is missing or mismatched, report the iframe version through the rejected
      port, and keep the host's READY validation. Preserve
      `WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` as the stable failure for SDKs
      that implement the current validator.
- [ ] Publish the matching host SDK and upgrade every known embedding
      application as part of the breaking cutover. Do not add an old-message
      compatibility branch to the iframe.
- [ ] Replace `ActiveWalletSessionV1` plus separately transported credential
      pairs with the identity-coupled exact browser boundary type.
- [ ] Delete `registration_established_wallet_session_v1`,
      `RegistrationEstablishedSessionTokens`, and
      `walletSessionTokenForCurve` after registration and unlock responses emit
      the exact browser record directly.
- [ ] Delete unused `ActiveWalletSession` aliases that do not denote the exact
      V2 projection.
- [ ] Delete wallet-specific JWT marker constants and the generic wallet JWT
      decoder after their final diagnostic caller is removed.
- [ ] Preserve console-session JWT types in the console packages.
- [ ] Preserve the frozen `reusable_wallet_session` Router A/B wire and
      transcript discriminator, the ECDSA export-share authorization kind, and
      the applied `consume_reusable_wallet_session` quota kind. These strings
      describe the reusable operation protocol and do not denote the retired V1
      bearer tables.

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

### K. D1 schema and deployment manifests

Historical migrations remain immutable, including:

- `0001_signer_d1_initial.sql`;
- `0002_signer_post_103_canonical_upgrade.sql`;
- `0003_r107_wallet_authorization.sql`;
- `0007_r103p8_wallet_session_auth_method_provenance.sql`; and
- `0016_r103e_wallet_session_authorizations_v2.sql`.

`linked_device_wallet_session_authorizations` and
`linked_device_wallet_session_quotas` were already dropped by immutable
`0015_r103e_authority_baseline.sql`. R103F adds no deletion work for those
historical tables.

R103F requires two remaining logical migration stages, each represented by a new
forward file. The first is a corrective/additive bridge migration that replaces
the landed exact-only `0024` trigger and adds the bridge schema. The second is the
later enforcement/deletion migration. Allocate their numbers only after
synchronizing the landed migration directory with every known pending migration
from concurrent workstreams and serializing the migration-owning branches.
Reserve the next unused numbers in that combined manifest, then recheck
immediately before commit and after every rebase. Resolve a race by renaming only
unapplied drafts with their owners; applied and landed shared-history files remain
immutable. Allocation from the landed tree alone is insufficient, and the two
new R103F numbers need not be contiguous.

There is no V1-bearer-to-V2 backfill: plaintext V1 credentials cannot be
recovered from their hashes, and a curve-scoped V1 token is not an exact V2
primary credential.

Registration side-effect cleanup is separate from V1 bearer backfill and runs
as Phase 0 security remediation. Build one bounded D1 remediation command that
selects only the two registration record-key prefixes, parses each known
completion shape, retires any still-usable bearer resolved from that row, and
rewrites it to the credential-free V2 receipt or deletes it when no replay state
must remain. It records before/after counts and aborts on an unknown shape or an
unmappable usable credential. It never scans or rewrites unrelated versioned
JSON records or logs credential-bearing row bodies.

Commit `03b39d34f` landed these three migrations on `dev`:
`0023_r109d_first_email_linked_device.sql`,
`0024_r103f_v2_authorized_operation_claim.sql`, and
`0025_r109d_email_enrollment_wallet_cardinality.sql`. Their numbers are consumed.
Do not rewrite, rename, or discard `0024`. First determine which persistent
environments, if any, applied it and record the exposure window for old-worker
all-null-scope claims. The corrective/additive migration must safely replace its
trigger on both clean databases and databases where `0024` already ran. Allocate
that new file and the later deletion file from the combined landed-and-pending
manifest; at the current checkpoint the next landed number is `0026`, subject to
another concurrent-allocation check immediately before creation. The planned
R115 `wallet_recovery` authority-provenance migration participates in that
allocation even though it has no draft yet, and it remains ordered after the two
R103F stages.

1. **Additive cutover migration**
   - use the existing `linked_scope_org_id`, `linked_scope_project_id`, and
     `linked_scope_env_id` columns on ordinary authorized-operation rows;
   - add the V2 hosted child-credential and exchange tables;
   - add `linked_device_wallet_session_credential_deliveries_v1` with complete
     link, session, recipient, sealed-envelope, acknowledgement lifecycle, and
     crash-resumable cleanup-receipt bindings;
   - reference the exact linked installation and V2 authorization from each
     delivery row with composite foreign keys and unique full-scope link and
     credential-digest constraints;
   - adopt `linked_device_authority_allocations` into migration-owned schema:
     create it for clean databases, accept an existing runtime-created table
     only after schema-parity validation, then delete its runtime initializer;
   - make hosted child credentials reference their exact V2 parent through a
     composite foreign key and make each child digest unique;
   - admit fully scoped rows through the V2 trigger branch, admit all-null scope
     from old workers through the V1 branch during the bounded rollout, and
     reject partially populated scope;
   - preserve valid existing V2 rows with non-null credential digests;
   - classify V2 rows with null credential digests as unusable and report them;
   - leave V1 tables intact so an old worker can finish during rolling deploy;
   - emit counts for active V1, active usable V2, active V2 without a
     credential, pending V1-authorized operations, unconsumed hosted exchange
     codes, V1-only quotas, and credential-bearing completion rows under each
     registration side-effect prefix.
2. **Enforcement and deletion migration**
   - run only after every worker uses the exact Wallet Session model and the
     maximum old session, hosted exchange, and pending-operation lifetime has
     drained;
   - abort when active V1 sessions, pending V1-authorized operations, or
     unconsumed V1 hosted exchanges remain; deployment preflight separately
     proves that no old worker revision is serving traffic;
   - retire V2 rows whose primary credential digest is null;
   - rebuild `wallet_session_authorizations_v2` with a check requiring every
     active row to have a primary credential digest;
   - rebuild parent and child tables in an explicit deferred-foreign-key order,
     preserve and recreate hosted-child and linked-delivery composite foreign
     keys, then have the deployment preflight execute `PRAGMA
     foreign_key_check` or the equivalent D1 query and abort unless its result
     set is empty;
   - automatically retire only null-credential or logically expired duplicate
     V2 rows. Abort when more than one usable credential-bearing non-retired row
     remains for an exact tuple; require operator-visible remediation instead of
     selecting an arbitrary survivor;
   - install the exact-tuple partial unique index only after that deterministic
     preflight returns zero duplicate usable tuples;
   - retain completed historical authorized-operation rows for replay, while
     requiring complete V2 scope on every pending/new authorization-grant row;
   - remove the V1 trigger branches;
   - drop or rebuild V1 child tables before dropping their parent foreign key;
   - drop `opaque_wallet_session_tokens` and the V1 hosted exchange table;
   - delete V1-only quota rows that are referenced by neither V2 nor a retained
     completed operation;
   - drop `reusable_wallet_sessions`, its indexes, and its triggers; and
   - leave no view or alias reproducing V1.

### Rolling-deploy contract

The cutover uses three application stages followed by a separate deletion
migration:

1. **Direct-response, storage-tolerant precursor.** Publish an SDK that parses
   the direct exact issuer response, still writes the V5 pair, and treats
   unknown future Wallet Session rows as preserved `upgrade_required` state.
   Deploy `walletSessionClientCapability` on every route in the issuance matrix
   and then enforce it. Record the final unmarked issuance time. Existing
   unmarked sessions may operate during the bounded drain, but cannot extend
   their lifetime.
2. **Bridge worker and final browser record.** After the maximum unmarked session
   lifetime drains or the approved invalidation completes, apply the additive migration and
   deploy the bridge worker. It issues new sessions and operations directly as
   fully scoped V2 while temporary compatibility at request and D1 persistence
   boundaries accepts already-issued V1 bearers and all-null-scope pending V1
   operations. Both precursor and final SDK receive the same direct issuer wire
   response; the precursor persists V5 and the final SDK persists
   `record_version: 6`. Publish the final SDK and matching iframe only after this
   storage gate passes. Final readers and installers contain late precursor
   writes. The bridge never projects a V1 bearer into V2, and core V2 functions
   never accept a compatibility shape.
3. **Exact-only worker.** Confirm no bridge-predecessor worker revision is
   serving traffic. Start the V1/pending-operation/hosted-exchange drain clock,
   wait the recorded maximum lifetimes or perform the explicitly approved
   invalidation, and prove zero active V1 sessions, pending V1-authorized
   operations, and unconsumed V1 hosted exchanges. Delete the temporary
   TypeScript boundary branches only after the rollout-receipt normalization
   reaches zero capability-tagged receipts. Then delete the client-capability
   field, deploy the exact-only worker, and confirm every serving revision is
   exact-only.
4. Apply the enforcement/deletion migration in a separate deployment.

Completed historical operations remain replayable without a source-activity
lookup. Pending old-worker rows with all-null scope use the temporary V1
persistence reader until the pre-exact drain gate passes. Storage-tolerant
precursor tabs may coexist with `record_version: 6` through the documented
shared-store rules.
Pre-precursor tabs become unsupported when their unmarked session expires or the
approved invalidation occurs; the first `record_version: 6` write cannot occur
before that gate.

The worker drain covers HTTP request and D1 persistence compatibility. It does
not cover an npm host SDK talking to a deployed iframe. Before the final iframe is
deployed, publish the matching SDK, upgrade every known embedding application,
and record the intentional break for remaining old embeds. The exact READY
version check fails closed across either skew direction.

Do not place the enforcement/deletion migration on a branch consumed by the
deployment workflow until the drain and exact-only-worker checks pass; the
migration runner applies every pending file before worker deployment.

Update required-table manifests after the deletion migration:

- [ ] `packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts`;
- [ ] `packages/wallet-console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts`.

### L. Tests, fixtures, guards, and docs

Classify each failure before editing it. Delete assertions that protect V1
persistence or fallback. Preserve exact admission and user-visible behavior.

High-priority test inventory:

- [ ] `tests/unit/d1AuthorizationCore.unit.test.ts`;
- [ ] `tests/unit/d1OwnerProofWalletSessionIssuance.unit.test.ts`;
- [ ] `tests/unit/d1WalletAuthMethodStore.unit.test.ts`;
- [ ] `tests/unit/d1WalletSessionAuthMethodProvenance.unit.test.ts`;
- [ ] `tests/unit/linkedDeviceManagement.unit.test.ts`;
- [ ] `tests/unit/walletSessionAuthorizationStatus.unit.test.ts`;
- [ ] `tests/unit/walletSessionExpiry.boundaryAndServer.unit.test.ts`;
- [ ] `tests/unit/registrationEstablishedWalletSessionProjection.unit.test.ts`;
- [ ] `tests/unit/syncAccount.yaoOrchestration.unit.test.ts`;
- [ ] `tests/unit/routerAbEd25519YaoRecoveryWalletSessionAuthorization.unit.test.ts`;
- [ ] `tests/unit/walletExecutionAdmissionV2.unit.test.ts`;
- [ ] `tests/unit/walletExecutionLanePreflight.unit.test.ts`;
- [ ] `tests/unit/ecdsaV2PoolFillAdmission.unit.test.ts`;
- [ ] `tests/unit/syncAccountYaoEnrichment.domain.guard.unit.test.ts`;
- [ ] `tests/unit/nearPublicApi.walletSessionAuthorization.unit.test.ts`;
- [ ] `tests/unit/walletHostOwnerAuthority.unit.test.ts`;
- [ ] `tests/unit/walletSessionOperationCredential.unit.test.ts`;
- [ ] `tests/unit/walletIframeHost.emailOtpRecoveryCodes.unit.test.ts`;
- [ ] `tests/unit/relayWalletRegistration.boundary.unit.test.ts`;
- [ ] `tests/unit/ed25519YaoSealedRefreshPersistence.unit.test.ts`;
- [ ] `tests/unit/d1LinkedDeviceAuthorityInstallService.unit.test.ts`;
- [ ] `tests/unit/deviceLinkingRoutes.unit.test.ts`;
- [ ] `tests/unit/linkDeviceAuthorityResume.unit.test.ts`;
- [ ] `tests/unit/authMenuPasskeyContinuation.unit.test.ts` when client linking
      orchestration changes, preserving the explicit terminal retry state when
      the other device cancels;
- [ ] `tests/unit/emailOtpEcdsaSigningRefreshRuntimeScope.unit.test.ts`;
- [ ] `tests/unit/passkeyEd25519YaoWarmRecovery.unit.test.ts`;
- [ ] `tests/unit/walletRecoverySourceSelection.unit.test.ts`, preserving oldest
      active RP-matching Passkey selection and the auth-method-ID tie-breaker in
      the presence of sibling methods;
- [ ] `tests/unit/walletRecoveryFinalization.unit.test.ts`, preserving exact
      selected-source retirement while committed replay accepts active sibling
      methods and envelopes;
- [ ] `tests/unit/scanDevice.firstEmail.unit.test.ts` when client linking
      orchestration changes, preserving first-Email routing and release of the
      wallet iframe foreground surface while Device 1 waits;
- [ ] `tests/unit/qrCodeScanner.progress.unit.test.ts` when scanner/progress UI is
      touched, preserving interactive cancellation and opener focus;
- [ ] atomic direct-V2 issuance failure/replay tests;
- [ ] registration side-effect receipt tests proving activation and deferred NEAR
      provisioning persist no plaintext primary/child credential or
      credential-bearing response field, while replay returns the exact
      credential-free committed installation projection;
- [ ] bounded registration-journal remediation test covering both prefixes,
      known-shape rewrite/deletion, unrelated-record preservation, unknown-shape
      and unmappable-credential abort, matched usable-bearer retirement, old-writer
      quiescence, repeated zero count, and zero credential-bearing rows afterward;
- [ ] Phase 0 registration compatibility test proving the old-client adapter
      reconstructs the current projection and signs a V1 bearer only in memory,
      keeps fingerprint and committed projection identity stable while bearer
      bytes may differ, and still satisfies the deployed exact-key response
      parser; plus a deletion test proving the adapter is unreachable when
      `already_committed` becomes authoritative;
- [ ] contract-drift update proving
      `packages/wallet-server/src/core/threeRouteRegistrationContracts.ts`, the
      registration-service replay comment, and the staging-cohort assertion no
      longer promise byte-identical credential-bearing terminal bytes;
- [ ] server-issued `already_committed` replay test proving no plaintext is
      fabricated and the next exact-method unlock replaces the orphaned session;
- [ ] lost founding-registration response contracts for Passkey and Email OTP:
      terminate the page/worker after server commit and before the response,
      reload from `PendingWalletRegistrationCommitV1`, replay to
      `already_committed`, atomically publish local discovery state, exact-method
      unlock installs the exact browser record, and immediate signing succeeds;
- [ ] classify any assertion that the final direct-exact registration replay
      returns a fresh V1 bearer as `obsolete_test_or_fixture`; replace it with the
      pending-commit + credential-free projection → exact-method unlock contract.
      Keep one dedicated Phase 0 adapter test only until the adapter's deletion
      gate, then delete that test with the adapter;
- [ ] mint replay/replacement tests proving the same mint returns the same
      identity and a successor requires a fresh mint;
- [ ] exact material-resolution tests assigning or deleting every legacy opaque
      runtime-binding field without synthesized identifiers;
- [ ] linked activation credential-digest replay tests;
- [ ] linked sealed-delivery loss tests: lost response, failed exact-record write, worker
      termination and recipient-handle loss, delivery expiry, lost
      acknowledgement, and acknowledged cleanup. Recipient loss must resume the
      durable local install and exact-method unlock rather than start a new link;
- [ ] linked credential-delivery recipient/AAD binding and cross-session stale
      acknowledgement tests;
- [ ] linked acknowledgement crash-injection tests after delivery tombstone,
      ciphertext removal, allocation deletion, link-session deletion, and
      cleanup completion; every local bootstrap replay resumes and completes
      exactly once;
- [ ] route-level acknowledgement replay test proving a request after active
      link-session deletion authenticates through the bounded cleanup receipt,
      resumes the remaining transition, and never returns an early `not_found`;
- [ ] linked local-prerequisite transaction tests proving crash atomicity,
      pending-record invisibility, idempotent receipt replay, and terminal
      rejection cleanup that preserves pre-existing local records; both landed
      server-worker-activation-pending and session-issuance-pending reasons
      remain retryable without a second authority;
- [ ] migration-owned linked-install schema parity test after deleting runtime
      `CREATE TABLE` copies;
- [ ] exact-record session/credential identity-coupling type and parser fixtures;
- [ ] exact-record `replaceExactActive` test proving same-method predecessor retirement
      and sibling-method preservation in one transaction, including a late V3,
      V4, or V5 write that cannot abort installation;
- [ ] exact-reader conversion tests with two active sibling methods proving
      signing, export, funding, refresh, management, readiness, and source-claim
      callers use their declared tuple/selection source and never wallet-wide
      uniqueness or insertion order;
- [ ] exact-record startup quarantine test covering a legacy row written by an already
      open old tab after initial cleanup;
- [ ] shared-IndexedDB skew tests proving the storage-tolerant precursor preserves
      and ignores a future browser row instead of returning `corrupt`, current
      exact-record readers contain a
      late precursor write, and both supported versions reach a terminal UI;
- [ ] precursor issuance-gate test proving an unmarked client cannot mint,
      refresh, or replace after the drain clock starts;
- [ ] direct-response precursor matrix proving every issuance boundary accepts
      the named client capability, returns the direct exact issuer response,
      persists V5 in the precursor, records the response family for replay, and
      rejects missing or changed replay capability without rotating a
      credential;
- [ ] rollout-receipt normalization test proving unknown tags abort, known tags
      become the credential-free final `already_committed` projection, no
      credential is created, and the tagged-receipt count reaches zero before the
      parser is deleted;
- [ ] typed expired/exhausted/retired/revoked V2 reader tests;
- [ ] authorized-operation full-scope claim and replay tests;
- [ ] hosted child-credential nominal-type, disjoint-prefix, issue/redeem/use
      transport-Origin, iframe-parent-Origin, quota, parent-lifecycle, and
      primary-preservation tests, including issue rejection for an unauthorized
      but self-consistent `walletOrigin`;
- [ ] authority/material-promotion tests proving all affected sibling-method V2
      snapshots update without rotating session, quota, mint, or credentials;
- [ ] promotion response-loss test proving exact readback reconciles the browser record before
      the promoted runtime becomes active;
- [ ] same-authority sibling-method promotion test proving one promotion response
      or exact readback reconciles every affected local browser record. Do not model a
      different linked-device authority as affected;
- [ ] host SDK/iframe protocol-skew tests in both directions, with removed
      reusable-session message fields rejected;
- [ ] targeted IndexedDB cleanup preservation test;
- [ ] wallet-bootstrap contract covering empty storage, valid exact-record restore, and
      obsolete or malformed session rows without a blank application shell;
- [ ] exact auth-method and authority revocation transaction tests;
- [ ] current Passkey recovery exact-model finalization/replay test, proving the
      selected source's exact session retires, sibling-method sessions remain
      active, and the replacement's normal login issues one exact session;
- [ ] rolling-deploy migration tests covering an old-worker all-null-scope V1
      claim, a fully scoped V2 claim, partial-scope rejection, and pending V1
      replay through the temporary persistence boundary;
- [ ] clean-database and deployed-history migration tests, including deletion
      abort conditions, multiple usable exact-tuple rejection, deterministic
      retirement of only unusable/expired duplicates, and a programmatic
      assertion that foreign-key check returns zero rows;
- [ ] Router A/B Wallet Session claim fixture helpers; and
- [ ] stale inline JWT-shaped session fixtures found by the zero-reference
      search.

Intended-behaviour and operating-path inventory:

- [ ] `tests/e2e/intended-behaviours/passkey.registration.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/email-otp.registration.benchmark.test.ts`;
- [ ] `tests/e2e/intended-behaviours/passkey.unlock.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/email-otp.unlock.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/passkey.recovery.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/refactor93-staging-cohort.staging.test.ts`
      registration replay assertion: replace byte-identical terminal output with
      stable committed projection plus a valid parsed adapter response;
- [ ] `tests/e2e/intended-behaviours/auth-method-addition.matrix.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/passkey.add-email-otp.contract.test.ts`;
- [ ] `tests/e2e/intended-behaviours/email-otp.add-passkey.contract.test.ts`; and
- [ ] `tests/e2e/linked-device.operating-path.test.ts` for all four source and
      target factor combinations.

Source guards:

- [ ] retire or replace
      `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`;
- [ ] update `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs` to
      forbid V1 tables, `not_v2`, V3 client records, and opaque-token fallback
      in production code while preserving the frozen Router A/B
      `reusable_wallet_session` and quota discriminators;
- [ ] prefer exact behavioral and type fixtures over adding more source-text
      matching.

Documentation:

- [ ] update `docs/threshold-ecdsa/ecdsa-threshold-signing.md`;
- [ ] update `docs/auth-gating-routes.md`;
- [ ] update `docs/intended-behaviours.md` and the registration contracts for
      the lost-response replay transition. Update the current recovery contract
      only where R103F changes its Wallet Session representation;
- [ ] update `packages/wallet/README.md`;
- [ ] correct R103E, R107, and R109D completion ledgers where they currently
      imply the cutover already finished; and
- [ ] mark this document complete only after the zero-reference ledger passes.

## Implementation Phases

### Phase 0 — Baseline, simplify the change surface, and remove persisted plaintext

- [ ] Record the baseline commit SHA and `git status --short`. Identify which
      pre-existing working-tree changes belong to R103F before counting or
      editing them.
- [ ] Save the exact tracked production-file list and its total line count,
      excluding SQL, tests, generated artifacts, and documentation. Reuse that
      same file list for the completion delta.
- [ ] Build the preparatory liveness ledger for each large R103F target. Record
      proof for `obsolete_or_unreachable` paths and separately report deleted,
      moved, and net live production lines.
- [ ] Delete only proved dead or obsolete code. Preserve every temporary rollout
      boundary until its named drain gate. Classify affected tests and remove
      fixtures or guards that protect only retired behavior.
- [ ] Perform the bounded registration extractions in the order defined above,
      one file and one cohesive seam at a time. Keep deletion, movement, and
      behavior changes reviewable as separate commits and run the narrowest
      existing verification after each movement.
- [ ] Record the landed migration directory plus every pending migration from
      concurrent workstreams. Treat landed `0023`, `0024`, and `0025` as consumed
      and immutable. Determine which persistent environments applied exact-only
      `0024`, record any old-worker claim exposure, and make the next R103F file a
      forward corrective/additive migration that is safe whether `0024` already
      ran or appears earlier in the same clean-database migration batch. Reserve
      the later R115 authority-provenance rebuild in the same ownership ledger
      and keep it after both R103F migrations.
- [ ] Record the exact V2 issue, persistence, read, admission, retirement, and
      replay functions that remain after the cutover.
- [ ] Freeze mint semantics and the narrow full-scope V2 replay lookup. Prove a
      same-mint retry returns one committed identity and replacement requires a
      fresh mint.
- [ ] Freeze `PendingWalletRegistrationCommitV1` and the credential-free
      committed registration projection. Prove that their combination can
      complete local discovery and exact-method unlock after a page reload,
      while neither record contains a Wallet Session credential or exposes a
      pending wallet as active. Freeze that same projection as the sole source
      for the adapter's non-credential response fields.
- [ ] Assign every legacy opaque runtime-binding field to an authoritative exact
      material resolver or to a deletion. Stop if a live consumer would require
      a synthesized threshold identity.
- [ ] Freeze the exact `record_version: 6` composite and add type fixtures so it
      cannot omit authority, method, authorization ID, Wallet Session ID, quota
      ID, capability subjects, or the primary credential.
- [ ] Prove statically that a hosted child credential cannot be constructed as
      a primary credential, the two raw encodings resolve to disjoint tables,
      and linked replay cannot accept a new digest or recipient.
- [ ] Freeze material-promotion continuity: list every exact server field that
      changes and every identity that remains stable, plus the response-loss
      browser-record reconciliation path.
- [ ] Freeze and vector-test the linked credential-delivery envelope and exact
      AAD using the existing server-supported P-256 ECDH/AES-256-GCM WebCrypto
      construction. Prove the same contract works for all four factor pairs.
- [ ] Inventory every known npm host-SDK embed, freeze the bidirectional
      CONNECT/READY version contract, and record the coordinated upgrade owner
      for each embed.
- [ ] Run one current intended path for Passkey and one for Email OTP, including
      signing immediately after unlock or linking, and save the command/result.
      Start services through the current post-`06e960b35`
      `tests/scripts/start-intended-services.mjs` configuration; do not reuse
      historical hard-coded local ports from older evidence.
- [ ] Establish a green focused baseline for
      `tests/unit/authMenuPasskeyContinuation.unit.test.ts`. At the
      post-`d676e7d22` checkpoint, 23 of its 25 cases pass. Triage the two
      pre-existing mismatches before R103F production changes: the local-wallet
      account-sync case still expects an exact requested wallet while
      `8751f7229` deliberately enters the discoverable `walletId: null` sync
      branch, and the Email OTP device-link case omits the now-required target
      email introduced by `03b39d34f`. Resolve each against intended behavior,
      then update or delete stale assertions and fixtures instead of adding a
      compatibility branch to production.
- [ ] Run `tests/e2e/linked-device.operating-path.test.ts` before production
      changes. Record prerequisites, exact command, current result, and failure
      classification so Phase 7 can distinguish baseline failure from cutover
      regression; no green composed-run baseline is assumed. Record whether each
      cross-factor case starts from the genuine single-method inventory required
      by R109D, especially Passkey-only to first-Email enrollment.
- [ ] Capture D1 counts for active V1 rows, usable V2 rows, V2 rows with null
      credential digests, opaque tokens, pending V1-authorized operations,
      hosted exchanges, V1-only quotas, and credential-bearing completion rows
      under each registration side-effect prefix.
- [ ] Replace registration activation and deferred NEAR provisioning journals
      with the credential-free receipt shape. Assemble an issued credential only
      in live response memory. Deploy the receipt writer, strict receipt parser,
      and bounded V1 replay adapter as one compatibility release; never expose an
      `already_committed` body to a client that still parses only the legacy
      terminal shape. Keep the adapter until the pending-commit client and direct
      exact issuer are deployed; final replay then maps the same projection to
      `already_committed`.
- [ ] In that same compatibility release, update the Route 3 contract and service
      comments and replace the staging byte-identical replay assertion. Preserve
      idempotency/fingerprint and committed-projection identity while explicitly
      allowing fresh adapter bearer bytes.
- [ ] Deploy that compatibility release independently of the wider exact Wallet
      Session cutover. Prove that no old completion writer revision is serving,
      wait the maximum in-flight request window, and only then run the bounded D1
      remediation over both prefixes. Preserve unrelated records, retire each
      mapped usable bearer, abort on unknown or unmappable shapes, record
      before/after counts, and never emit row bodies to command output or logs.
- [ ] Repeat the zero-credential query after the maximum in-flight request
      window. Record D1 backup/time-travel retention and either complete an
      approved purge or retain the security exposure until every affected
      bearer is proved retired or expired.
- [ ] Verify zero registration completion rows retain `walletSessionToken`, a
      primary or child operation credential, or a credential-bearing public
      response.
- [ ] Record the maximum lifetime of every V1 session, hosted exchange, and
      pending-operation claim that determines the deletion drain window. Record
      the response-replay lifetime and count every durable receipt carrying the
      temporary client capability; treat an unbounded lifetime as requiring
      terminal receipt normalization rather than a time-only drain.

Exit: dead and obsolete R103F paths are deleted with evidence, the registration
extractions preserve behavior, the target contract and real data shapes are
known, new registration journals are credential-free,
historical credential-bearing registration rows are removed or redacted, their
usable bearers are retired or expired, and the current intended paths still
pass.

### Phase 1 — Land additive schema support

- [ ] Bind and validate the existing authorized-operation scope columns, then
      add the dual V1/V2 trigger boundary in a new forward migration.
- [ ] Add V2 hosted child-credential and exchange storage.
- [ ] Add the linked credential-delivery table with its recipient, sealed
      envelope, exact-session, acknowledgement, and digest constraints.
- [ ] Move `linked_device_authority_allocations` to migration-owned schema and
      preserve immutable `0018` as the only definition of
      `linked_device_authority_installations`.
- [ ] Add the hosted-child composite V2 foreign key and unique credential
      digest, including rebuild-safe foreign-key verification.
- [ ] Add migration counters and abort conditions.
- [ ] Make duplicate cleanup deterministic: retire only null-credential or
      logically expired rows and abort if multiple usable credential-bearing
      rows remain for an exact tuple.
- [ ] Assert in the migration harness that the foreign-key check result set is
      empty after the ordered parent/child rebuild.
- [ ] Apply the migration to a clean database and a database produced by every
      immutable historical migration in order.
- [ ] Prove the migration leaves the current worker operational during rolling
      deploy and does not mutate applied migration fingerprints.
- [ ] Delete runtime linked-installation `CREATE TABLE` strings once the forward
      migration is authoritative, then prove clean and historical databases use
      the same schema.

Exit: the schema supports the bridge worker while old workers can finish their
bounded rollout through request- and persistence-boundary compatibility.

### Phase 2 — Issue exact server authorizations atomically

- [ ] Create one direct server issuer returning the persisted V2 record, quota,
      and primary credential after their atomic commit.
- [ ] Add a prepared linked-activation path that generates the credential,
      seals it to the authenticated dedicated Device 2 credential recipient,
      and commits the digest plus sealed delivery in the activation CAS.
- [ ] Convert founding registration, unlock, refresh, sync, recovery, and linked
      activation one call site at a time.
- [ ] Make a lost founding-registration response replay return
      `already_committed`, validate and atomically promote the durable pending
      local registration, transition through exact-method unlock, install the
      exact browser record, and sign without a fresh registration ceremony.
- [ ] Keep the durable registration journal on its Phase 0 credential-free
      receipt shape while converting its public first-execution response to the
      exact browser-record boundary. Delete the temporary V1 replay adapter in
      the same release that makes `already_committed` authoritative.
- [ ] Convert material promotion so its authority CAS updates every affected V2
      projection while preserving session, quota, mint, and credential identity.
- [ ] Extend the authenticated active V2 status response to return the complete
      digest-free exact projection used for lost-response and bootstrap
      reconciliation.
- [ ] Normalize every converted response into the exact browser record and persist
      it before publishing authenticated UI state.
- [ ] Add failure injection proving a failed batch exposes neither an active
      session nor a quota, and a replay cannot rotate a credential.
- [ ] Delete each corresponding projection call immediately after conversion.

Exit: every issuance path is atomic and direct. No production caller issues V1
before V2, and linked activation replay preserves its original credential.

### Phase 3 — Make operation admission exact-only

- [ ] Require the V2 operation-credential reader.
- [ ] Return the exact typed lifecycle union from persistence and map it to
      stable non-500 route responses.
- [ ] Delete `not_v2` and opaque-token fallback from both curve validators.
- [ ] Convert signing, pool fill, signing-session seal, execution-lane preflight,
      recovery warm bootstrap, and operation step-up.
- [ ] Bind authorized-operation claims and replays to full V2 scope, exact
      method/authority, quota, capability, and material activation.
- [ ] Preserve same-method step-up for exhausted sessions and fresh step-up for
      exports.

Exit: exact V2 is the only normal signing, export, and execution path. The
temporary rollout resolver remains isolated at the request and persistence
boundaries until Phase 6 drains existing V1 credentials and pending claims.

### Phase 4 — Cut the client to the exact browser record

- [ ] First implement the storage-tolerant precursor reader and its terminal
      `upgrade_required` state without enabling `record_version: 6` writes. Make
      it parse the direct exact issuer response into V5 and add the temporary
      client capability at every boundary in the issuance matrix.
- [ ] Convert every `readActiveForWallet` caller from the frozen 40-call-site
      ledger. Require its declared tuple, current selection, credential-bound
      identity, or intentional multi-record result and delete the wallet-wide
      singleton reader after the zero-reference check.
- [ ] Remove V3 writes, merges, parsers, and curve token selection.
- [ ] Delete V4/V5 active pair shapes and normalize all response boundaries
      directly into the identity-coupled exact browser record.
- [ ] Make exact-record `replaceExactActive` the only install path and prove it retires
      exact same-method predecessors while preserving siblings. It quarantines
      known legacy rows inside the same transaction, preserves unknown future
      rows, and does not abort on a late precursor write.
- [ ] Reject a deliberately mismatched session/credential pair at parsing and
      before IndexedDB persistence.
- [ ] Remove iframe and public API fallback shapes.
- [ ] Run targeted row cleanup in the existing Wallet Session store. Delete
      active V3/V4/V5 rows, preserve valid `record_version: 6` rows and intentional
      exact tombstones, and
      leave every wallet, authority, method, signer-material, export-root, and
      recovery-code store unchanged.
- [ ] Run targeted quarantine on every current bootstrap and ignore obsolete
      rows in all readers, including rows written later by an old open tab.
- [ ] Reconcile material-promotion responses or exact readback into every
      affected same-authority sibling-method browser record before activating the promoted
      runtime.
- [ ] Prove clearing or upgrading Wallet Session rows cannot erase wallet
      discovery or signer state.

Exit: the precursor release is future-row tolerant, and the final release reads
and writes only current exact active records and intentional exact tombstones.
Each final-version bootstrap and install contains any obsolete row it observes,
including a late write from a precursor tab. No `record_version: 6` production
write is enabled before the Phase 6 precursor gate.

### Phase 5 — Convert administration and boundary routes

- [ ] Convert session status, hosted exchange, identity management, public-key
      reads, authenticator inventory, custody ownership upgrade, funding, and
      factor release.
- [ ] Apply the route policy matrix above and preserve each route's current
      capability, assurance, and quota policy.
- [ ] Convert auth-method and authority revocation to atomic V2 retirement.
- [ ] Convert current recovery finalization, replay, and post-recovery session
      behavior to the exact model. Preserve deterministic oldest
      RP-matching-Passkey selection, selected-source replacement, and sibling
      preservation. Do not implement R115's later selected-source preservation.
- [ ] Implement hosted child credentials and prove redeeming one leaves the
      primary credential valid.
- [ ] Require hosted issue `walletOrigin` to equal authenticated tenant
      deployment metadata or a server-side allowlist entry.
- [ ] Prove parent replacement, explicit retirement, method revocation, and
      authority revocation retire hosted children in the owning transaction;
      parent expiry fails logically at resolution.
- [ ] Convert device-link source resolution and post-install authenticated
      state to V2.
- [ ] Make Device 2 prerequisites durable before credential decrypt, implement
      recipient-loss recovery through resume plus exact-method unlock, and make
      final acknowledgement cleanup idempotently resumable across every delete.
- [ ] Extend the existing local-install transaction to include the pending
      wallet profile and authenticator, and prove terminal rejection cannot
      leave a partially discoverable wallet or delete pre-existing state.
- [ ] Move acknowledgement replay authentication to the live-session-or-cleanup-
      receipt boundary so deletion of the active link session cannot make the
      remaining cleanup transitions unreachable.

Exit: all current-session wallet routes normalize one exact V2 context. Only the
explicit bridge resolver may invoke the V1 boundary until Phase 6 removes it.

### Phase 6 — Coordinated deployment, drain, and V1 deletion

- [ ] Stage 1: publish the direct-response, storage-tolerant precursor SDK with
      `record_version: 6` writes disabled. Confirm it parses the direct exact
      issuer response into V5, preserves unknown future rows, never reports them
      as legacy corruption, and cannot overwrite them.
- [ ] Deploy and enforce `walletSessionClientCapability` on every route in the
      issuance matrix. Record the final unmarked issuance time, then wait its
      maximum V1 lifetime or perform the explicitly approved invalidation. Do
      not enable `record_version: 6` before this gate.
- [ ] Stage 2: apply the additive migration and deploy the bridge worker. New
      issuance and operation claims are V2; existing V1 bearer and pending-row
      support remains isolated at request and D1 persistence boundaries.
- [ ] Publish the final host SDK, upgrade every known embedding application, bump
      `WALLET_PROTOCOL_VERSION`, add it to CONNECT, and verify both postMessage
      version-skew directions fail with
      `WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH` before the iframe adopts the port
      or the host marks the connection complete.
- [ ] Deploy the matching iframe and enable `record_version: 6` writes only after
      both the shared-IndexedDB precursor gate and host/iframe handshake gate pass.
- [ ] Run the narrow intended operating paths against the deployed schema.
- [ ] Confirm no pre-bridge worker revision is serving traffic, then start the
      separate V1 bearer, pending-operation, and hosted-exchange drain clock.
- [ ] Wait the recorded maximum V1 drain window or explicitly invalidate the
      environment after user approval.
- [ ] Confirm zero active V1 sessions, pending V1-authorized operations,
      and unconsumed V1 hosted exchanges.
- [ ] Stage 3: delete the temporary request/persistence compatibility branches
      after normalizing every durable capability-tagged receipt to the final
      credential-free `already_committed` projection. Assert zero tagged
      receipts, delete the client-capability field and parser, deploy the
      exact-only worker, and confirm every serving revision is exact-only.
- [ ] Apply the enforcement/deletion migration without editing applied SQL.
- [ ] Abort the enforcement deployment if multiple usable credential-bearing V2
      rows remain for an exact tuple or if the programmatic foreign-key check
      returns any row.
- [ ] Verify the final schema and counters on a clean database and a
      representative deployed-history database.
- [ ] Remove V1 tables from readiness manifests.

The short-lived compatibility needed during rollout lives only at the request,
IndexedDB persistence, and D1 persistence boundaries plus the additive
migration's trigger. It never promotes a V1 bearer into V2. All TypeScript
compatibility branches and the client-capability field are deleted before the
exact-only worker is declared deployed.

Exit: all deployed code uses only the exact Wallet Session model and the V1
schema is absent.

### Phase 7 — Delete V1 production code and close acceptance

- [ ] Delete all remaining unused V1 store, service, port, parser, type, and
      route code in the inventory.
- [ ] Close every preparatory liveness-ledger entry: delete each proved
      `obsolete_or_unreachable` path, verify every retained `live_unrelated` root,
      and delete each `rollout_boundary` path whose named drain gate closed.
- [ ] Review the final extracted modules for forwarding-only wrappers, cyclic
      dependencies, duplicate validators, compatibility re-exports, and helpers
      used by only one caller. Inline or delete them unless they make a domain
      boundary materially clearer.
- [ ] Remove stale tests, fixtures, source guards, and docs.
- [ ] Report deleted lines, moved lines, and the net live production-line delta
      separately from SQL, tests, generated artifacts, and documentation.

Run only the verification needed to prove the operating contract first:

1. Passkey registration → immediate NEAR and EVM-family signing.
2. Email OTP registration → immediate NEAR and EVM-family signing.
3. Page or worker termination loses a Passkey or Email OTP founding-registration
   response → reload reads the invisible `PendingWalletRegistrationCommitV1` →
   ceremony replay returns `already_committed` with the credential-free committed
   projection → one local transaction publishes discovery/auth/signer state →
   exact-method unlock installs the exact browser record → immediate signing.
4. Registration activation and deferred NEAR provisioning → durable side-effect
   rows contain only credential-free commit receipts → replay returns the
   committed projection → the temporary Phase 0 old-client adapter signs a V1
   bearer only in memory and passes the old exact-key parser, with stable
   committed identity rather than byte-identical bearer output → after adapter
   deletion both historical prefixes contain zero plaintext credentials and
   every exposed bearer is retired or proven expired across active and retained
   backup copies.
5. Lock/reload → exact-method unlock → immediate signing.
6. An exact-record same-method replacement retires its local predecessor while a
   sibling method's record remains active.
7. Device link for all four source/target factor combinations from genuine
   single-method source inventories → Passkey-only-to-Email exercises first-Email
   enrollment and Email-only-to-Passkey adds no source Passkey → immediate
   signing and export availability on Device 2 without a second unlock.
8. Replay linked activation after lost response or acknowledgement → same
   sealed delivery, exact session, credential, and recipient binding remain
   usable; after active link-session deletion, the matching acknowledgement
   authenticates through only its bounded cleanup receipt, removes ciphertext
   once, and resumes cleanup without an early `not_found`.
9. Terminate Device 2 after server activation and lose the recipient handle, or
   let the delivery expire → the atomically persisted, non-discoverable local
   prerequisite transaction survives intact → resume publishes its durable local
   authority state → exact-method unlock retires the unreachable session and signs
   without a second link. A terminal rejection deletes only newly pending records
   and preserves pre-existing wallet state.
10. Crash acknowledgement cleanup after each state transition → exact replay
    resumes delivery tombstone, ciphertext removal, allocation cleanup,
    link-session cleanup, and completion exactly once.
11. Wallet Session exhaustion → typed exhausted result → same-method step-up.
12. Expired, retired, revoked-method, and revoked-authority sessions return typed
   failures and never HTTP 500/503.
13. Exact auth-method revocation → revoked session and hosted children rejected,
    sibling method remains.
14. Authority revocation → only that authority's sessions, quotas, and hosted
    children retire.
15. Authority/material promotion → every affected exact server authorization and
    same-authority sibling-method browser projection updates before the runtime
    activates, while session, quota, mint, and primary credentials remain
    unchanged. Lost response reconciles through the full exact projection read.
16. Current Passkey recovery with two active RP-matching Passkeys and an active
    Email OTP sibling → the oldest Passkey is selected with auth-method ID as
    tie-breaker → only the selected source, its envelope, and its exact session
    retire → sibling methods, envelopes, and sessions remain active → committed
    replay succeeds → normal replacement-Passkey login issues one exact session
    and signs.
17. Key export → fresh exact-method step-up.
18. Hosted exchange redemption → nominal child credential works only across its
    stored app-issue, wallet-redeem/use, and iframe-parent origins while the
    primary credential remains valid.
19. Hosted exchange issue with an unauthorized but self-consistent
    `walletOrigin` → rejected before any exchange row or child credential exists.
20. Targeted IndexedDB cleanup → old session rows disappear while wallet
    discovery, methods, signer materials, export roots, and recovery codes remain.
21. Every route in the issuance matrix receives
    `direct_exact_response_future_record_tolerant` → returns the direct exact issuer
    response → the precursor normalizes it to V5 while the final SDK normalizes
    the same wire response to `record_version: 6`; replay preserves the recorded
    response family during the bridge period and a changed capability returns a
    typed failure without rotating a credential. Before parser deletion, durable
    tagged receipts normalize to credential-free `already_committed` and the
    tagged count reaches zero.
22. A storage-tolerant precursor sees a future browser row → preserves and ignores
    it without returning `corrupt` or blanking the shell → reaches terminal
    `upgrade_required` when its own session cannot continue. If a precursor later
    writes V5 during exact-record replacement, the current SDK quarantines it, the
    install still commits, and no current reader returns it.
23. A mismatched exact browser record/credential pair is rejected before
    persistence.
24. Old host SDK/new iframe and new host SDK/old iframe combinations fail at the
    exact protocol handshake before Wallet Session data is exchanged.
25. The first production `record_version: 6` write remains disabled until the
    named client capability is enforced on every issuance route and every
    unmarked issuance lifetime has drained or been invalidated.
26. Management and request-boundary routes satisfy the policy matrix.
27. Empty storage, a valid exact browser record, and an obsolete or malformed
    session row each render the correct wallet/authentication UI without a blank
    shell or loss of IndexedDB wallet discovery.
28. Enforcement migration with multiple usable exact-tuple rows or any
    foreign-key-check result row → deployment aborts; unusable/expired duplicates
    follow the deterministic retirement policy.

Then run the narrow type checks and focused server/client units affected by the
cutover. Run broader repository gates only after the user authorizes them.

Exit: the intended operating paths pass, manual testing is unblocked, the
deletion ledger and zero-reference searches pass, and R103F contains no
provisional language.

## Zero-Reference Closure Ledger

The following searches must have no production matches except immutable
historical migrations or explicitly named historical documentation:

```bash
rg -n "reusable_wallet_sessions|opaque_wallet_session_tokens" \
  packages crates wasm apps

rg -n "issueReusableWalletSession|readReusableWalletSessionStatus|\
resolveOpaqueWalletSessionToken|issueOpaqueWalletSessionToken|\
readOpaqueWalletSessionTokenByIdentity" packages

rg -n "not_v2|readActiveForWallet|wallet_session_authorization_v3|\
WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V4|\
WALLET_SESSION_AUTHORIZATION_RECORD_VERSION_V5" \
  packages apps

rg -n "issueWalletSessionAuthorizationV2FromReusableSession|\
refreshWalletSessionAuthorizationV2FromReusableSession|\
projectReusableWalletSessionV2" packages

rg -n "mintRouterAbEd25519YaoWalletSessionV1|\
issueRouterAbEd25519OpaqueWalletSessionToken|walletSessionPolicyMintId|\
ReusableWalletSessionMintId|parseReusableWalletSessionMintId" \
  packages

rg -n "registration_established_wallet_session_v1|\
RegistrationEstablishedSessionTokens|walletSessionTokenForCurve" \
  packages apps

rg -n "operation_credential_hash =|\
putWalletSessionAuthorizationV2OperationCredential|\
issueWalletSessionAuthorizationV2OperationCredential" \
  packages/wallet-server/src

rg -n "walletSessionClientCapability|direct_exact_response_future_record_tolerant" \
  packages apps
```

Allowed matches after completion:

- immutable applied migration sources;
- this deletion ledger and historical refactor records; and
- migration fingerprint tests that prove those historical files did not
  change.

The singular `reusable_wallet_session` Router A/B discriminator and
`consume_reusable_wallet_session` quota discriminator are intentionally absent
from this zero-reference ledger. They remain frozen protocol vocabulary.

No allowlist may conceal a live production reference.

## Completion Criteria

R103F is complete only when all of the following are true:

- every ordinary Wallet Session is issued directly as an exact server
  authorization;
- every active exact server-authorization row has its primary credential digest
  from the same atomic issuance or activation transaction;
- registration activation and deferred provisioning journals persist only
  credential-free commit receipts, and both historical prefixes contain zero
  plaintext operation credentials after the Phase 0 remediation;
- one credential-free committed installation projection supplies both the
  adapter's non-credential legacy response fields and final
  `already_committed` recovery; no parallel receipt shape exists;
- the compatibility release deploys the receipt writer, parser, and V1 replay
  adapter together, and its Route 3 contract, service comment, and tests describe
  stable committed identity rather than byte-identical bearer bytes;
- every operation credential exposed by a historical completion row is retired
  or proven expired, no old writer can recreate one, and the disposition of
  retained D1 backup/time-travel copies is recorded;
- a lost founding-registration response resumes only from a validated pending
  local commit plus the credential-free server projection, publishes all local
  discovery/auth/signer state in one transaction, and then unlocks the exact
  method;
- browser and wire session types contain no persisted credential digest;
- linked activation replay cannot rotate its primary credential;
- linked credential replay remains bound to its original Device 2 recipient and
  exact acknowledgement identity;
- linked-device acceptance covers all four source/target factors from genuine
  single-method source inventories, including Passkey-only to first-Email
  enrollment;
- Device 2 persists every local profile, authenticator, method/factor, authority,
  and signer-installation prerequisite in one non-discoverable pending
  transaction before the activation request, and resume can finalize any pending
  local method before credential decrypt; terminal rejection removes only newly
  pending state, while recipient loss or delivery expiry recovers through resume
  plus exact-method unlock;
- linked acknowledgement removes ciphertext and completes allocation/session
  cleanup through an exact, crash-resumable state machine, and remains
  authenticated through the bounded cleanup receipt after active link-session
  deletion;
- client persistence has one identity-coupled exact active representation with
  `record_version: 6`;
- the exact-record parser proves its credential and session IDs match;
- the exact browser record stores its actual Wallet Session ID under the existing
  `wallet_session_id` keyPath and its authorization ID under
  `authorization_id`;
- exact-record installation retires same-method predecessors in one local
  transaction while preserving siblings;
- current-SDK bootstrap quarantines observed V3/V4/V5 rows and no current reader
  returns a row later written by an old tab;
- a deployed precursor SDK parses the direct exact issuer response into V5 and
  preserves unknown future rows; the final SDK parses the same wire response into
  `record_version: 6`; unmarked issuance is fenced and drained before the first
  final-record write; every tagged rollout receipt is normalized to the
  credential-free final projection; and the temporary client capability is
  absent from both durable data and the exact-only release;
- sibling auth methods may each retain one exact active session;
- every former `readActiveForWallet` caller names or derives its exact
  authority/method selection, credential identity, or intentional multi-record
  result;
- no signing, export, link, recovery, management, or hosted-exchange route
  falls back to V1;
- all status, replay, quota, source, and revocation checks resolve the fully
  scoped exact identity and return typed lifecycle failures;
- hosted child credentials resolve their exact parent identity, share its quota,
  leave its primary credential unchanged, and use a nominal type and encoding
  that cannot resolve as primary;
- hosted issue accepts only the authoritative server-side tenant wallet origin;
- every parent-retirement transaction also retires hosted children;
- authority/material promotion updates all affected exact projections atomically,
  returns or reads the complete digest-free exact projection, and reconciles
  every same-authority sibling-method browser record before the promoted runtime
  becomes active;
- the exact iframe protocol handshake rejects host SDK version skew before any
  Wallet Session message is accepted;
- current recovery deterministically replaces only the selected oldest
  RP-matching Passkey, retires only its exact session and envelope, preserves
  siblings, and uses the exact Wallet Session model without adopting R115's
  selected-source preservation;
- IndexedDB cleanup removes only obsolete Wallet Session rows;
- no V1 bearer is promoted or reinterpreted as an exact operation credential;
- V1 tables and triggers are removed by forward migration;
- enforcement aborts on multiple usable exact-tuple survivors and on any
  foreign-key-check result row;
- V1 session-storage and bearer APIs, types, parsers, tests, and fixtures are
  deleted while frozen reusable-operation protocol discriminators remain;
- no `ReusableWalletSessionMintId` symbol or compatibility alias remains, while
  persisted and frozen wire mint field names retain their current spelling;
- every preparatory liveness-ledger item is closed, all proved dead or obsolete
  code is deleted, all drained rollout boundaries are deleted, and extracted
  modules contain no compatibility re-exports or duplicate live implementation;
- the twenty-eight operating acceptance paths above work;
- the zero-reference ledger passes; and
- the final production source line count over the saved baseline file list is
  lower than the recorded baseline.

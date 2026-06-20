# Router A/B Spec

Date consolidated: June 20, 2026

Status: canonical Router A/B architecture and protocol reference. This document
replaces the deleted Router A/B signer, Wallet Session, ECDSA-HSS, and future
quorum planning docs. Deployment profile and rollout details live in
[router-a-b-deployment.md](./router-a-b-deployment.md). Local commands and smoke
coverage live in [router-a-b-local-dev.md](./router-a-b-local-dev.md). Historical
cleanup closure lives in [router-a-b-cleanup.md](./router-a-b-cleanup.md).

## 1. Overview

Router A/B is the split-custody signing architecture for SDK/server Ed25519 and
ECDSA-HSS product signing. The browser sees one public backend, the Router.
Router owns public admission and private worker forwarding. Deriver A, Deriver B,
and SigningWorker stay behind private service boundaries.

Current local/core status:

- Ed25519 and ECDSA product signing use Router A/B only.
- Old public threshold signing routes are deleted from active product signing.
- Wallet Session bearer JWT auth is the public signing authorization boundary.
- Server-authoritative signing budget and step-up behavior are owned by
  [refactor-70-server-budget.md](./refactor-70-server-budget.md).
- No-HSS unlock, material restore, and deeper worker-owned material cleanup are
  owned by Refactor 74/75.
- Deployed Cloudflare evidence belongs in
  [router-a-b-deployment.md](./router-a-b-deployment.md).

Product signing topology:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

Derivation-time topology for registration, export, recovery, refresh, and
activation:

```text
Client -> Router -> Deriver A
                -> Deriver B
                -> SigningWorker when activation output is needed
```

Deriver A and Deriver B leave the hot signing path after activation. Normal
Ed25519 and ECDSA signing use Router plus SigningWorker.

## 2. Roles And Boundaries

### 2.1 Router

Router owns public HTTP routes, Wallet Session JWT verification, policy,
replay, quota, abuse checks, signing-budget reserve/commit/release, request
binding, CORS, diagnostics, observability, and private-worker forwarding.

Router may hold:

- public metadata and public keys
- typed request scope
- opaque ciphertext
- public transcript digests
- replay state
- lifecycle records
- budget reservations and counters
- public activation and delivery receipts

Router must never hold both raw sides of protected split values. Router must not
open deriver plaintext envelopes, client output packages, SigningWorker output
packages, raw root material, canonical ECDSA private keys, or Ed25519 HSS client
base material.

### 2.2 Deriver A And Deriver B

Deriver A and Deriver B own role-local derivation material. They receive only
role-specific encrypted envelopes and authenticated role-bound peer messages.

Deriver A may hold A-side root/provisioning material and A-side protocol state.
Deriver B may hold B-side root/provisioning material and B-side protocol state.
Neither deriver receives enough material to reconstruct client or server signing
material alone.

Derivers must reject:

- wrong-role envelopes
- stale key epochs
- stale root-share epochs
- wrong peer identity
- wrong transcript digest
- expired requests
- replayed nonces
- malformed output-recipient labels
- mixed client-recipient and SigningWorker-recipient output

### 2.3 SigningWorker

SigningWorker owns activated server-side signing material, one-use nonce state,
Ed25519 presign-pool state, ECDSA-HSS presignature state, Ed25519 finalize
execution, and ECDSA-HSS prepare/finalize execution.

SigningWorker private routes require internal service auth and admitted Router
requests. SigningWorker does not parse browser Wallet Session credentials.

SigningWorker may open only material addressed to the active SigningWorker
identity. It must reject output packages for clients, derivation workers, stale
activation epochs, wrong public identity, or wrong active-state session ids.

### 2.4 Browser SDK And WASM Workers

TypeScript SDK code is orchestration only. It carries public/session metadata,
Wallet Session JWTs, typed lifecycle state, runtime policy scope, SigningWorker
scope, worker material handles, binding digests, public facts, and route
requests.

`crates/signer-core` and browser WASM workers own client-side cryptographic
protocol logic, crypto-secret material, key/share derivation, binding checks,
nonce/client-base state, ECDSA-HSS client signing shares, presign/client-share
material, PRF-derived secret state, and signing-share generation.

TypeScript must not own raw Ed25519 HSS client-base material, raw ECDSA-HSS
client signing shares, presignature secrets, nonce secrets, PRF.first bytes, or
signing shares.

Persisted worker material handles are hints. A sign-ready runtime capability
exists only after the current worker validates the handle and binding for the
current Wallet Session, signing grant, threshold session, signing root, runtime
policy scope, SigningWorker id, client verifier, and material binding digest.

## 3. Security Model

Router A/B targets this split-custody invariant:

```text
server never has joined d, a, x_client_base
client never has joined d, a, y_server, tau_server
client opens only x_client_base
SigningWorker opens only x_server_base
```

Split values are algebraic relationships, not transport payloads:

```text
y_server = y_A + y_B
tau_server = tau_A + tau_B
y_client = y_client_A + y_client_B
tau_client = tau_client_A + tau_client_B
```

No Router, deriver, coordinator, persistence layer, log sink, or diagnostics path
may receive both raw sides of a protected split value.

Threat containment matrix:

| Compromise | Expected exposure | Required containment |
| --- | --- | --- |
| Router | Public metadata, ciphertext, hashes, timings | No deriver plaintext, root shares, output shares, or signing shares |
| Deriver A | A custody material and A local derived material | No B plaintext, no joined `d`, no joined `a`, no `x_client_base`, no `x_server_base` |
| Deriver B | B custody material and B local derived material | No A plaintext, no joined `d`, no joined `a`, no `x_client_base`, no `x_server_base` |
| SigningWorker | Activated server signing material and nonce/presign state | No `k_org`, no joined root, no client material, no Deriver A/B root material |
| Client | User client material and local worker handles | No server root material, no `y_server`, no `tau_server` |
| Logs/observability | Public metadata, hashes, timings, state transitions | No protocol payload plaintext or secret material |

Initial release claim:

```text
Router A/B Level C prevents a single production server process from holding
joined d, a, x_client_base, y_server, or tau_server during derivation-time
ceremonies, assuming the role-separated protocol boundary is followed.
```

This is a split-custody and boundary claim. It is not a full malicious-secure
MPC proof system.

## 4. Protocol Decisions

### 4.1 Split Derivation Primitive

Production Router A/B split derivation uses `mpc_threshold_prf_v1`.

Reasons:

- It preserves continuity with the current threshold-PRF root custody model.
- It keeps the same wallet identity story across hosted and self-hosted modes.
- It already has native proof-path performance that is acceptable for setup,
  export, refresh, and recovery.
- It has the clearer correctness-hardening, refresh-continuity, and
  formal-verification path.

The split-root derivation candidate remains prototype material. It needs fresh
vectors, leakage analysis, root-generation review, anti-bias review, and refresh
or address-verification acceptance before promotion.

### 4.2 Role-Separated HSS Boundary

Production Router A/B code uses role-separated HSS APIs. Joined-state executor
APIs remain outside production Router A/B paths.

Allowed role-separated API inputs:

- role-local root material
- role-local client material
- transcript metadata
- authenticated peer protocol messages
- request-kind-specific scope

Forbidden production inputs and outputs:

- joined `d`
- joined `a`
- joined `y_server`
- joined `tau_server`
- joined `x_client_base`
- joined hidden-word executor state
- evaluator driver state that lets one worker reconstruct protected values

Allowed outputs:

- encrypted client-output package shares
- encrypted SigningWorker-output package shares
- public transcript digest
- typed redacted diagnostics

Draft role-separated API shape:

```rust
pub struct RoleSeparatedHssInput<R> {
    pub role: R,
    pub transcript: TranscriptBinding,
    pub local_root_material: RoleLocalRootMaterial<R>,
    pub local_client_material: RoleLocalClientMaterial<R>,
    pub peer_messages: Vec<AuthenticatedPeerMessage>,
}

pub struct RoleSeparatedHssStepOutput<R> {
    pub role: R,
    pub peer_messages: Vec<AuthenticatedPeerMessage>,
    pub client_output_package: Option<EncryptedClientOutputPackage>,
    pub signing_worker_output_package: Option<SigningWorkerOutputPackage>,
    pub transcript_digest: TranscriptDigest,
    pub diagnostics: RedactedCeremonyDiagnostics,
}

pub trait RoleSeparatedHssEngine<R> {
    fn advance(
        &mut self,
        input: RoleSeparatedHssInput<R>,
    ) -> Result<RoleSeparatedHssStepOutput<R>, HssRoleError>;
}
```

### 4.3 SigningWorker Placement

Normal signing uses a standalone SigningWorker. Deriver A and Deriver B are not
in the normal-signing hot path. Activation ceremonies deliver server-recipient
output to SigningWorker, then SigningWorker owns active server-side signing
state.

Initial topology:

```text
Registration/export/recovery/refresh:
  Client -> Router -> Deriver A and Deriver B
  Deriver A <-> Deriver B
  Deriver A/B -> SigningWorker
  SigningWorker activates x_server_base
  SigningWorker -> Router activation receipt

Normal signing:
  Client -> Router -> SigningWorker -> Router -> Client
```

### 4.4 Non-Circular Envelope Binding

Deriver-envelope construction must be non-circular. Public pre-envelope
transcript context is separate from encrypted-envelope assignment metadata.

Digest ordering:

1. `PublicRouterRequestContextV1::context_digest()` covers public request fields
   excluding role envelopes, role-envelope AAD digests, and ciphertext bytes.
2. `PublicRouterRequestContextV1::derivation_transcript_digest()` covers
   derivation scope, deriver set, selected SigningWorker, client identity,
   client ephemeral key, request kind, root-share epoch, and the public request
   context digest.
3. Role-envelope AAD binds the known derivation transcript digest and Router
   request context digest.
4. `PublicRouterRequestV1::router_replay_digest()` covers the full public
   request, including encrypted role envelopes, for Router replay and
   idempotency storage only.

Role envelopes must carry typed AAD supplied by Router. Deriver private service
bodies require `aad.digest()` to match the envelope's public `aad_digest`.

### 4.5 Output Correctness Levels

Initial release target: Minimum Level C.

Minimum Level C requires:

- Router never opens joined secret material.
- Deriver A and Deriver B never open joined secret material.
- SigningWorker opens only its server-recipient output.
- Client opens only client-recipient output.
- Source guards reject joined-state executor imports in production Router A/B
  paths.
- Transcript and output package digests bind role, request kind, deriver set,
  root-share epoch, SigningWorker id, client identity, and replay nonce.

Later hardening may add stronger output correctness checks, public commitments,
DLEQ-style proofs, TEE-backed role execution, or provider-diverse role placement.
Those are future protocol/profile decisions.

## 5. Ceremony And Transcript Model

### 5.1 Request Kinds

One `DerivationCeremony` lifecycle covers request-kind-specific scope:

- `registration`
- `key_export`
- `recovery`
- `server_share_refresh`
- `activation_refresh`

Normal signing is not a derivation ceremony. It consumes active SigningWorker
state.

### 5.2 Ceremony States

Canonical lifecycle shape:

```rust
pub enum DerivationCeremony {
    Created(CreatedCeremony),
    Admitted(AdmittedCeremony),
    AEnvelopeForwarded(AEnvelopeForwardedCeremony),
    BEnvelopeForwarded(BEnvelopeForwardedCeremony),
    AbRunning(AbRunningCeremony),
    ClientOutputReady(ClientOutputReadyCeremony),
    SigningWorkerOutputReady(SigningWorkerOutputReadyCeremony),
    Activated(ActivatedCeremony),
    Failed(FailedCeremony),
    Expired(ExpiredCeremony),
    Abandoned(AbandonedCeremony),
}
```

Required common scope:

- `request_id`
- `protocol_version`
- `request_kind`
- `account_id` or `wallet_id`
- `session_id`
- `org_id`
- `project_id`
- `environment_id`
- `signing_root_id`
- `signing_root_version`
- `root_share_epoch`
- Deriver A identity and key epoch
- Deriver B identity and key epoch
- SigningWorker identity and key epoch
- client ephemeral public key
- transcript nonce
- expiry

State rules:

- `Created` contains parsed public metadata and encrypted-envelope digest
  metadata.
- `Admitted` contains accepted or reused expensive-work gate state.
- `AbRunning` has both deriver envelopes forwarded and peer identities pinned.
- `ClientOutputReady` exposes only encrypted client-output packages.
- `SigningWorkerOutputReady` exposes only SigningWorker-output packages.
- `Activated` records SigningWorker activation receipt and public identity.
- `Failed`, `Expired`, and `Abandoned` are terminal except for explicit
  idempotent status reads.

### 5.3 Transcript Binding

Transcript binding covers all public facts that define the ceremony:

- protocol version
- request kind
- request id
- replay nonce
- account or wallet id
- rp id or chain target
- org/project/environment
- signing root id and version
- root-share epoch
- deriver set id
- Deriver A id and key epoch
- Deriver B id and key epoch
- SigningWorker id and key epoch
- client ephemeral public key
- recipient kind (`client` or `signing_worker`)
- output package kind
- request expiry
- public request context digest

Transcript digest must not depend on encrypted envelope ciphertext, role-envelope
AAD digest, or any digest that depends on itself.

### 5.4 Direct A/B Coordination

After Router forwards role envelopes, Deriver A and Deriver B coordinate through
authenticated transcript-bound peer messages:

```text
Router -> A: A envelope, public request metadata
Router -> B: B envelope, public request metadata

A -> B: protocol message A1
B -> A: protocol message B1
A -> B: protocol message A2
B -> A: protocol message B2

A -> Router: encrypted client package A, public delivery metadata
B -> Router: encrypted client package B, public delivery metadata
A -> SigningWorker: encrypted SigningWorker proof bundle A
B -> SigningWorker: encrypted SigningWorker proof bundle B
SigningWorker -> Router: activation receipt/status
```

A/B messages may contain commitments, masks, OT/correlation messages, encrypted
labels, or output shares. They must not contain raw joined values or plaintext
material intended for another role.

### 5.5 Output Delivery

Client output:

```text
A -> Client: EncryptToClient(x_client_A package)
B -> Client: EncryptToClient(x_client_B package)
Client opens x_client_base = x_client_A + x_client_B
```

SigningWorker output:

```text
A -> SigningWorker: EncryptToSigningWorker(x_server_A package)
B -> SigningWorker: EncryptToSigningWorker(x_server_B package)
SigningWorker opens x_server_base = x_server_A + x_server_B
```

Output packages bind request kind, transcript digest, recipient identity, role,
root-share epoch, signing root, account/wallet identity, and expiry.

## 6. Public And Private API

### 6.1 Public Route Families

Current public signing-capable route families:

- Ed25519 Wallet Session issuance: `/v2/router-ab/wallet-session/ed25519`
- Ed25519 HSS lifecycle: `/v2/router-ab/ed25519/hss/*`
- Ed25519 normal signing: `/v2/router-ab/ed25519/sign/*`
- ECDSA-HSS Wallet Session/bootstrap/lifecycle: `/v1/hss/ecdsa/*`
- Wallet Session seal: `/v2/wallet-session/seal/*`
- Wallet Session budget status: `/session/signing-budget/status`

Old public threshold signing routes are not active product signing paths:

- `/threshold-ed25519/authorize`
- `/threshold-ed25519/sign/*`
- `/threshold-ed25519/presign/refill`
- `/threshold-ecdsa/authorize`
- `/threshold-ecdsa/presign/*`
- `/threshold-ecdsa/sign/*`

Retained threshold-named paths, if any, must be non-signing compatibility
boundaries, private/internal routes, or historical source-guard fixtures with
explicit ownership.

### 6.2 Private Route Families

Private routes are internal service routes and require internal service auth:

- Deriver A private ceremony routes
- Deriver B private ceremony routes
- SigningWorker activation routes
- SigningWorker Ed25519 normal-signing routes
- SigningWorker ECDSA-HSS prepare/finalize routes
- SigningWorker ECDSA-HSS pool-fill put routes

Private routes receive admitted Router bodies. They do not parse browser cookies,
Wallet Session bearer tokens, publishable keys, or app-session credentials.

### 6.3 Wallet Session Credential

Wallet Session is the only browser-facing signing authorization concept. The SDK
sends bearer Wallet Session JWTs to public Router A/B signing routes.

A signable Wallet Session state binds:

- wallet/account id
- threshold session id
- signing grant id
- runtime policy scope
- signing root id and version where applicable
- Wallet Session JWT
- participant set
- SigningWorker id and scope
- curve-specific Router A/B normal-signing state
- worker material handle or restorable worker material state
- binding digest and public verifier facts
- budget expiry and remaining-use information

Cookie-mode signing-capable sessions are rejected for Router A/B signing paths.
Legacy threshold JWT kinds are rejected at active signing-capable boundaries.

### 6.4 Normal-Signing Intent And Payload Binding

Router recomputes intent and signing-payload digests from typed request data.
The client is never the authority for the admitted signing digest.

Router creates internal admission candidates only after:

1. Wallet Session verification succeeds.
2. Request parsing succeeds.
3. Scope validation succeeds.
4. Intent digest recomputation succeeds.
5. Signing-payload digest recomputation succeeds.
6. Prepare/finalize binding validation succeeds.
7. Replay, quota, budget, policy, and abuse gates accept the request.

SigningWorker receives only admitted private request bodies.

### 6.5 Canonicalization Authority

`router-ab-core` owns canonical Router A/B byte encoding and digest derivation for
strict Router protocol surfaces. TypeScript and Cloudflare adapter code must use
shared vectors or boundary parsers for public request shapes, admission material,
request digests, replay digests, response digests, and active-state ids.

## 7. Ed25519 Normal Signing

Ed25519 Router A/B signing covers:

- NEAR transaction signing
- NEP-413 message signing
- NEP-461 delegate-action signing
- presign-pool hit signing
- presign-pool miss prepare/finalize signing

### 7.1 Route Sequence

Pool hit:

```text
POST /v2/router-ab/ed25519/sign
```

Pool miss:

```text
POST /v2/router-ab/ed25519/sign/prepare
POST /v2/router-ab/ed25519/sign
```

Pool refill:

```text
POST /v2/router-ab/ed25519/sign/presign-pool/prepare
```

Router admits the request, binds scope and request digest, reserves budget, and
forwards only admitted private material to SigningWorker. SigningWorker owns
server-side Ed25519 signing material and one-use pool/finalize state. The
browser worker owns Ed25519 HSS client material and signing-share generation.

### 7.2 Presign-Pool Semantics

Ed25519 presign-pool refill is message-agnostic. Refill must not carry intent
digest, signing-payload digest, or admitted signing digest.

A ready Router A/B Ed25519 presign entry includes:

- server round-1 handle
- server commitments
- server verifying share
- client nonce handle
- client commitments
- client verifying share
- account/session scope
- SigningWorker id
- expiry
- generation
- pool binding digest

Claim-time lookup validates account id, session id, signing root/key id when
available, SigningWorker id, client presign id, server round-1 handle,
generation, pool binding digest, and expiry before binding the record to an
admitted signing digest.

Burn semantics:

- Scope, handle, commitment, or expiry drift rejects before claim and preserves
  the pool record.
- Once a record is claimed for an admitted signing digest, cryptographic failure,
  invalid client signature share, or response-send uncertainty burns the record.
- Claimed nonce material never returns to the available pool.

### 7.3 Final Signing Boundary

Final Ed25519 signing consumes only a validated signable runtime state. Final
signing must not restore material, claim PRF, run HSS reconstruction, or fall
back to non-Router signing.

If material is absent or invalid, readiness must classify the lane as
`restore_available`, `material_pending`, or `material_restore_required` before
final signing begins.

## 8. ECDSA-HSS

ECDSA-HSS uses Router A/B for registration/bootstrap, activation, recovery,
refresh, export, presignature pool refill, and normal EVM/Tempo digest signing.

Protocol version:

```text
router_ab_ecdsa_hss_secp256k1_v1
```

### 8.1 Stable Context And Active-State Id

ECDSA-HSS active-state binding covers:

- stable key context
- signing root id and version
- ECDSA threshold key id
- public identity
- activation epoch
- participant set
- key handle
- threshold session id
- signing grant id
- runtime policy scope
- SigningWorker id
- Wallet Session JWT

Canonical active-state session id:

```text
{ecdsa_threshold_key_id}:{signing_root_id}:{signing_root_version}:{activation_epoch}
```

This value is the Wallet Session `session_id` for ECDSA-HSS normal signing and a
SigningWorker active-state lookup component. It prevents one wallet, key id, and
worker from colliding across signing root versions or activation epochs.

### 8.2 ECDSA Public Identity

Public identity equations:

```text
X_client = x_client * G
X_server = x_server * G
X = X_client + X_server
ethereum_address = last20(keccak256(uncompressed(X)[1..]))
```

SigningWorker activation verifies opened server material by deriving the public
server key and requiring the resulting public identity to equal the activated
identity. Refresh preserves public identity while advancing activation epoch.

Activation receipts include stable ECDSA-HSS context, public identity,
SigningWorker identity, activation epoch, activation digest, activated timestamp,
and SigningWorker output storage receipt.

### 8.3 Registration And Bootstrap

```text
Client -> Router: public ECDSA-HSS context, X_client, encrypted A/B envelopes
Router -> Deriver A: A envelope, public request metadata
Router -> Deriver B: B envelope, public request metadata
Deriver A <-> Deriver B: authenticated derivation protocol
Deriver A -> SigningWorker: encrypted SigningWorker activation bundle A
Deriver B -> SigningWorker: encrypted SigningWorker activation bundle B
SigningWorker -> Router: activation receipt with public ECDSA identity
Router -> Client: public identity, activation receipt, client-facing evidence
```

The SigningWorker opens only the material intended for it. Router can validate
public receipt shape, but cannot decrypt A/B envelopes or SigningWorker
activation bundles.

### 8.4 Explicit Export

```text
Client -> Router: export request, confirmation evidence, export nonce
Router -> Deriver A: A export envelope
Router -> Deriver B: B export envelope
Deriver A <-> Deriver B: authenticated export derivation protocol
Deriver A -> Router: encrypted client export bundle A
Deriver B -> Router: encrypted client export bundle B
Router -> Client: export bundles, metadata, delivery status
Client: opens export bundles, reconstructs x, verifies xG == X
```

Export requires Deriver A/B participation. SigningWorker does not release active
signing material for export.

Export is explicit, user-confirmed, transcript-bound, nonce/replay-protected,
auditable, and client-side reconstructed and verified.

Server-side export responses must never contain canonical `x`, `privateKeyHex`,
`x_client`, `y_client`, `y_server`, backend threshold private shares, or raw root
material.

### 8.5 Normal ECDSA Signing

ECDSA-HSS signing uses:

```text
POST /v1/hss/ecdsa/sign/prepare
POST /v1/hss/ecdsa/sign
```

Presignature pool refill uses:

```text
POST /v1/hss/ecdsa/presignature-pool/fill/init
POST /v1/hss/ecdsa/presignature-pool/fill/step
```

Normal signing uses activated SigningWorker state. Deriver A/B stay out of
online signing. If a signing mode needs client-side threshold participation,
that remains a client/SigningWorker signing protocol.

Presignature ids and handles are one-use. Replays, cross-session use, scope
mismatch, SigningWorker mismatch, activation-epoch drift, stale pool records, and
request-digest drift fail closed.

### 8.6 ECDSA Material Boundaries

| Material | Allowed location |
| --- | --- |
| `y_client` | Client only |
| `x_client` | Client only |
| Deriver A root/provisioning share | Deriver A only |
| Deriver B root/provisioning share | Deriver B only |
| Joined `y_server` | No single production worker |
| Joined `x_server` before activation | No Deriver or Router plaintext |
| Activated SigningWorker material | SigningWorker only |
| Canonical `x` / `privateKeyHex` | Authorized client export runtime only |
| ECDSA presign/triple/nonce material | SigningWorker/signing backend only |
| Public `X_client`, `X_server`, `X`, address | Public transcript after validation |

## 9. Admission, Replay, Budget, Expiry

### 9.1 Expensive-Work Admission

Expensive-work admission protects Router CPU, queue slots, Deriver CPU, Deriver
queues, and A/B protocol capacity.

Router derives gate context from trusted metadata:

- source IP or edge-provided client address
- authenticated user/session when present
- org/project/environment
- request kind
- account or wallet id
- normalized Email OTP email when present
- coarse device/session id where privacy-acceptable

The client may request an operation. It must not supply the gate decision or
gate identity.

Decision shape:

```ts
type ExpensiveWorkGateDecision =
  | { kind: 'accepted'; requestId: string }
  | { kind: 'reuse_existing'; requestId: string; existingLifecycleId: string }
  | { kind: 'defer'; reason: 'short_window_saturated' | 'deriver_queue_saturated' }
  | { kind: 'rejected'; reason: 'rate_limited' | 'abuse_policy'; retryAfterMs: number };
```

Operational rules:

- short-window gates default to one active expensive prepare per key per `5s` to
  `10s` in production
- duplicate normal-user clicks reuse the current pending lifecycle
- early precompute is independently disableable per deployment, org/project
  policy, or incident response state
- saturated deriver queues return `defer`
- rejected requests stop before Deriver A, Deriver B, or HSS prepare work
- gate records are short-lived, scoped, and cleaned up on completion, expiry, or
  abandon

### 9.2 Expiry

Worker/server time is authoritative. Wallet Session, prepare request, finalize
request, replay reservation, quota reservation, budget reservation, and
SigningWorker nonce/presign records are live only while `now_unix_ms <
expires_at_ms`. Exact equality is expired. Clock-skew allowance is `0 ms`.

Effective maximum lifetime is the minimum of request expiry, Wallet Session
expiry, active SigningWorker state expiry, replay reservation expiry, budget
reservation expiry, and private material expiry.

### 9.3 Replay

Replay checks run after authentication and scope validation and before budget
reserve where possible. Duplicate prepares should reuse idempotent prepared state
when the original request identity and digest match. Drift or mismatch rejects
without consuming budget or one-use signing material.

Finalize/sign replay is single-use. Once a nonce or presignature record is
claimed for an admitted signing digest, it cannot be reused for a different
request or returned to the pool.

### 9.4 Budget

Server-side Wallet Session budget is authoritative. SDK budget state is a local
projection only.

Signing routes use reserve/commit/release semantics:

```text
prepare
  -> validate Wallet Session JWT
  -> validate scope and signer binding
  -> reserve required server signature uses for signingGrantId
  -> forward admitted prepare to private SigningWorker
  -> return prepare response with budgetReservationId

finalize/sign
  -> validate Wallet Session JWT
  -> validate scope, request digest, and reservation binding
  -> forward admitted finalize to private SigningWorker
  -> release reservation if private SigningWorker finalization fails
  -> commit reserved server signature uses exactly once
  -> return signature only if SigningWorker finalization and budget commit both succeed
```

NEAR, Tempo, and EVM share the same Wallet Session budget when they share the
same `signingGrantId`. A post-exhaustion step-up mint creates a new signing
grant and budget counter.

## 10. Implementation Reference

### 10.1 Core Crates And Packages

`router-ab-core` owns:

- role-separated protocol types
- lifecycle state
- canonical bytes
- transcript binding
- request and response digest construction
- source guards
- local simulation primitives

`router-ab-cloudflare` owns:

- strict Router, Deriver A, Deriver B, and SigningWorker workers
- role-specific bindings
- private route boundaries
- Durable Object scopes
- activation state
- release checks

SDK packages own:

- typed Router A/B route clients
- Wallet Session state parsing
- worker material handle orchestration
- signable-state classifiers
- runtime policy scope binding
- browser Worker calls

### 10.2 Host Traits

Cloudflare and local development adapters should implement protocol-neutral host
traits for clock, RNG, key access, sealed share storage, Durable Object storage,
peer transport, internal service auth, and diagnostics sinks.

Core protocol logic should not import Cloudflare runtime types directly.

### 10.3 Bundle Discipline

Role bundles are separate. Router, Deriver A, Deriver B, and SigningWorker
entrypoints should include only the code needed by that role. Bundle size and
startup-time evidence belong in deployment docs and release evidence, not in this
spec.

### 10.4 Source Guards

Source guards should reject:

- production imports of joined-state HSS executor types in Router A/B paths
- public route parsing in private SigningWorker routes
- browser Wallet Session parsing in private worker code
- old public threshold signing route reintroduction
- client-visible Router normal-signing grants
- TypeScript access to raw Ed25519 client-base material or ECDSA signing shares
- logs containing protocol payload plaintext
- server export responses containing canonical private keys or raw root material

## 11. Observability, Runbooks, And Operations

### 11.1 Observability And Redaction

Diagnostics may include public ids, state transitions, duration metrics,
response sizes, request ids, transcript digests, role ids, key epochs, and safe
failure codes.

Diagnostics must not include raw protocol payloads, ciphertext plaintext, root
shares, nonce secrets, signing shares, private keys, PRF outputs, or worker
material handles that function as secrets.

### 11.2 Identity Pinning And Rotation

Deriver identity pinning binds Deriver A id/key epoch, Deriver B id/key epoch,
SigningWorker id/key epoch, deriver set id, root-share epoch, and deployment
profile into transcript scope.

HPKE signer-envelope key rotation supports current and previous epochs for a
bounded overlap window. Stale previous-epoch requests must be rejected after the
request TTL overlap expires.

### 11.3 Incident Response

Runbooks should cover:

- Router compromise
- Deriver A compromise
- Deriver B compromise
- Deriver A+B compromise
- SigningWorker compromise
- storage namespace errors
- KEK compromise
- replay-store reset
- CORS/origin misconfiguration
- key epoch rollback
- deployment manifest drift

Deployment-specific runbooks live in
[router-a-b-deployment.md](./router-a-b-deployment.md).

## 12. Future Work

Future protocol and deployment work includes:

- generalized N-of-N deriver sets
- t-of-N deriver quorum
- provider-diverse deployments
- TEE-backed SigningWorker or Deriver roles
- stronger output correctness proofs
- public commitments or DLEQ-style verification
- self-host export/import vectors
- distributed or approved-provisioning root-share refresh
- address/public-key parity gates after root-share refresh
- deployed HPKE rotation smoke evidence

Generalized quorum requires a new durable protocol version and transcript labels,
fresh cross-language vectors, leakage and collusion review, refresh/reshare
semantics, deriver-set binding, quorum selection, replay handling, equivocation
handling, duplicate-role tests, wrong-quorum tests, stale-epoch tests, and
mixed-recipient-output tests.

Router A/B v1 remains strict 2-of-2: Deriver A plus Deriver B.

## 13. Non-Goals

- Reintroducing old public threshold signing routes.
- Adding fallback from Router A/B signing to legacy signing paths.
- Treating deployment evidence as local cleanup evidence.
- Letting TypeScript own raw crypto-secret client material.
- Full malicious-secure MPC proof system in v1.
- Two-server online signing for every normal signature.
- Generalized quorum or provider-diverse deployment in Router A/B v1.

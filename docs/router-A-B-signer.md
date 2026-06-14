# Router A/B Deriver Architecture Plan

Date created: June 11, 2026

Status: design plan, prepared to start from Phase 0/Phase 1 after closing
refactor-66 as the retained registration baseline.

Spec:
[docs/router-A-B-signer-SPEC.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/router-A-B-signer-SPEC.md).

Follow-up refactor for the Candidate A `threshold-prf` backend adapter:
[docs/refactor-67-router-ab-threshold-prf-adapter.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/refactor-67-router-ab-threshold-prf-adapter.md).

## Goal

Add a split-server HSS derivation architecture with one public client endpoint:

```text
Client sees Router only.
Router handles auth/rate limits.
A and B receive only role-specific encrypted envelopes.
A and B coordinate directly.
Client-output shares are encrypted to the client.
SigningWorker-output shares go only to the standalone SigningWorker.
```

The target is to remove joined sensitive derivation state from any single
server-side production process during registration, key export, recovery, and
signing-worker share refresh.

Normal day-to-day signing should remain a client plus Router plus one
SigningWorker flow after the split setup path has produced the worker's allowed
output share.

## Security Target

This architecture targets the Level C invariant from the malicious-security
plan:

```text
server never has joined d, a, x_client_base
client never has joined d, a, y_relayer, tau_relayer
client opens only x_client_base
SigningWorker opens only x_relayer_base
```

The split values are algebraic relationships, not transport payloads:

```text
y_relayer = y_A + y_B
tau_relayer = tau_A + tau_B
y_client = y_client_A + y_client_B
tau_client = tau_client_A + tau_client_B
```

No router, deriver, coordinator, persistence layer, log sink, or diagnostics
path may receive both raw sides of a protected split value.

## Specification Decisions

Detailed protocol decisions and release gates live in the spec. Current
decisions:

- **Split derivation primitive:** `mpc_threshold_prf_v1` is selected for the
  production path. Its native proof path is sub-ms, and it has the clearer
  correctness-hardening, refresh-continuity, and formal-verification path
  through the existing `threshold-prf` machinery.
- **HSS integration boundary:** create a new role-separated API. Production
  Router A/B paths must not adapt current joined-state APIs in place.
- **Malicious correctness level:** ship Minimum Level C first. Stronger output
  correctness with verifying-share binding, commitments, relation checks, or
  proofs remains later hardening work subject to performance.
- **Signing worker placement:** normal signing uses a dedicated
  `SigningWorker`. Deriver A and Deriver B remain derivation workers for
  registration, key export, recovery, and signing-worker share refresh.
- **Deriver quorum:** v1 is a strict 2-of-2 A/B ceremony. Protocol and lifecycle
  types should still model an indexed deriver set internally so future N-of-N or
  t-of-N work can reuse the architecture after protocol review.
- **Lifecycle:** use one `DerivationCeremony` state machine with
  request-kind-specific scope.
- **Deriver identity and rotation:** bind protocol version, request kind,
  account/session, signing root version, root-share epoch, deriver A/B identity
  and key epochs, signing-worker identity and key epoch, client ephemeral key,
  Router request digest, nonce, and expiry into the transcript.
- **Observability:** use typed redacted diagnostics plus source guards.
- **Local/prod parity:** keep strict role, key, process, and wire-protocol
  separation from local simulation onward.
- **Rust/Wasm bundle discipline:** build separate role bundles and measure size,
  startup, and CPU for every release candidate.
- **Recovery/migration:** address verification is a release gate before
  production root rotation.

## Dedicated Signing Worker Update

Production Router A/B should use four worker roles:

```text
Router
Deriver A
Deriver B
SigningWorker
```

Deriver A and Deriver B are derivation workers. They participate in
registration, key export, recovery, and signing-worker share refresh
ceremonies, then leave the hot signing path. Normal signing uses:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

The `SigningWorker` is the single designated role that opens and stores the
server-side signing base material for normal signing. Router remains the only
public client API surface and continues to own auth, policy, quota, routing,
and observability. A and B stay off the normal-signing fallback path. Failover
uses multiple instances of the same `SigningWorker` identity or a refresh
ceremony that activates a new signing-worker identity.

Local development also has a bundled single-server profile:

```sh
pnpm router:bundled
pnpm router-ab:local:smoke:bundled
```

That profile exposes Router, Deriver A, Deriver B, and SigningWorker routes
from one process. It is useful for TEE-shaped deployments and customers that
choose one-server custody, but it is a weaker security profile than the
four-role deployment because process compromise reaches every role boundary.
The protocol routes remain explicit so the deployment can move back to
separate workers without changing client-facing semantics.

Activation delivery should support a direct Deriver A/B -> SigningWorker fast
path because activation latency matters. Router still owns the public request,
admission, replay, lifecycle, selected SigningWorker identity, and final client
response. Derivers send only SigningWorker-recipient ciphertext/proof bundles to
the SigningWorker, and the SigningWorker returns an activation receipt to
Router. SigningWorker never coordinates A/B derivation.

Use `Deriver A`, `Deriver B`, and `SigningWorker` for new design prose and
APIs. Older `SignerA`/`SignerB` and `Relayer` labels in current code,
environment variables, historical measurements, and route names are
transitional. The slimming refactor should rename them in one breaking pass so
the role names match their responsibilities.

## Topology

```text
                         direct authenticated A/B channel
                    +---------------------------------------+
                    |                                       |
                    v                                       v
+--------+     +----------+       +----------+        +----------+
| Client | --> |  Router  | ----> | Deriver A |        | Deriver B |
+--------+     +----------+       +----------+        +----------+
    ^               |                  |                   |
    |               |                  +-------------------+
    |               |                         A/B MPC
    |               v
    |          +---------------+
    |          | SigningWorker |
    |          +---------------+
    |                  |
    +------------------+
       encrypted client proof bundles and signing responses
```

The Router is the only public API surface used by clients. It authenticates the
user/session, applies rate limits, checks request shape, and forwards opaque
role-specific envelopes to A and B. It also forwards normal signing requests to
the active standalone SigningWorker.

Deriver A and Deriver B decrypt only their own envelopes, then coordinate
directly over mutually authenticated internal endpoints. The Router does not
broker A/B protocol messages in the primary design.

## Roles

### Client

- Derives client-side material.
- Splits client material into A-side and B-side shares.
- Encrypts role-specific envelopes for A and B.
- Sends one request to the Router.
- Receives encrypted client proof bundles from A and B through the Router.
- Opens only `x_client_base`.

The client must never receive joined `d`, joined `a`, `y_relayer`, or
`tau_relayer`.

### Router

- Owns public HTTP endpoints.
- Verifies session JWTs, auth context, request intent, account/project policy,
  quota, and abuse controls.
- Validates only public metadata and envelope framing.
- Forwards `a_envelope` to A and `b_envelope` to B.
- Aggregates encrypted response envelopes for the client.

The Router must treat deriver payloads as opaque ciphertext. It must never
decrypt deriver envelopes, inspect HSS state, combine A/B shares, or persist
protocol payload plaintext.

### Deriver A

- Holds A-side derivation material.
- Receives only A-side client shares.
- Runs the A role in the direct A/B protocol.
- Emits A-side client-output material encrypted to the client.
- Emits A-side signing-worker output material to the designated
  `SigningWorker`.

Deriver A must never receive B's raw shares or enough B-side state to reconstruct
joined `d`, `a`, or `x_client_base`.

### Deriver B

- Holds B-side derivation material.
- Receives only B-side client shares.
- Runs the B role in the direct A/B protocol.
- Emits B-side client-output material encrypted to the client.
- Emits B-side signing-worker output material to the designated
  `SigningWorker`.

Deriver B must never receive A's raw shares or enough A-side state to reconstruct
joined `d`, `a`, or `x_client_base`.

### Dedicated SigningWorker

- Receives signing-worker output shares only.
- Opens the server-side signing base material for normal signing.
- Handles normal signing with the client through Router after
  setup/export/refresh completes.

The `SigningWorker` is a dedicated worker role, separate from Deriver A and
Deriver B. Router must remain secret-light and must not activate or store the
server-side signing base material.

## Request Shape

The client sends one Router request containing public routing metadata and two
role-specific encrypted envelopes:

```ts
type RouterSplitDerivationRequest = {
  protocolVersion: string;
  requestKind: 'registration' | 'key_export' | 'recovery' | 'relayer_share_refresh';
  accountId: string;
  sessionId: string;
  transcriptNonce: string;
  expiresAtMs: number;
  clientEphemeralPublicKey: string;
  aEnvelope: EncryptedDeriverEnvelope;
  bEnvelope: EncryptedDeriverEnvelope;
};
```

Each encrypted deriver envelope must bind:

- `protocolVersion`
- `requestKind`
- `accountId`
- `sessionId`
- `transcriptNonce`
- `expiresAtMs`
- deriver role, `A` or `B`
- client ephemeral public key
- Router request digest

The plaintext inside `aEnvelope` is valid only for A. The plaintext inside
`bEnvelope` is valid only for B.

### Product-To-Primitive Request Mapping

Router-facing product operations remain more specific than primitive derivation
request kinds:

| Product operation       | Primitive request kind | Reason                                                                          |
| ----------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| `registration_prepare`  | `registration`         | creates the first account output relation after registration authorization      |
| `key_export`            | `export`               | re-opens existing account output material under export authorization            |
| `recovery`              | `export`               | re-opens existing account output material under recovery authorization          |
| `relayer_share_refresh` | `refresh`              | rotates future SigningWorker/root-share material and requires activation checks |

Recovery stays distinct in Router policy, auth, abuse controls, diagnostics,
and lifecycle state. It maps to primitive `export` because the derivation layer
does not create a new account relation for recovery; it releases existing
account-scoped output material after a different authority proof.

## Future N-Of-N And T-Of-N Generalization

Router A/B should ship first as a 2-of-2 system: Deriver A and Deriver B must both
participate in each derivation-time ceremony. Generalizing beyond two derivers is
useful future work, especially for operator diversity, maintenance windows, and
stronger availability, but it must not expand the first release's security
claim.

There are two future shapes:

- **N-of-N:** every configured deriver participates. This is the direct extension
  of A/B and mainly changes request framing, transcript binding, deriver-set
  management, and operational liveness. One unavailable deriver blocks the
  ceremony.
- **t-of-N:** any approved quorum can participate, such as 2-of-3 or 3-of-5.
  This is a larger protocol change. It requires threshold share indexing,
  quorum selection, transcript binding to the selected deriver set, replay and
  equivocation handling, commitments or verifying-share checks, and reviewed
  refresh/reshare semantics.

To keep the upgrade path open, v1 implementation should avoid hard-coding A/B
as a transport shape below the product API boundary. The protocol crate should
prefer deriver-set concepts even while enforcing `quorumPolicy = all(2)`:

```ts
type SplitDeriverSet = {
  deriverSetId: string;
  threshold: 2;
  derivers: readonly [
    { role: 'A'; deriverId: string; keyEpoch: string },
    { role: 'B'; deriverId: string; keyEpoch: string },
  ];
};

type RouterSplitDerivationRequestV1 = {
  protocolVersion: string;
  requestKind: 'registration' | 'key_export' | 'recovery' | 'relayer_share_refresh';
  deriverSet: SplitDeriverSet;
  deriverEnvelopes: readonly [RoleEncryptedEnvelope<'A'>, RoleEncryptedEnvelope<'B'>];
};
```

The public examples may continue to name `aEnvelope` and `bEnvelope` for
readability, but canonical transcript bytes should bind deriver-set id, deriver
index, role, key epoch, quorum policy, selected SigningWorker identity, and the
pre-envelope public request context. Encrypted-envelope digests are carried as
Router assignment metadata and validated against each role envelope. A future
t-of-N release should be a new protocol version with fresh vectors and leakage
analysis, not a silent expansion of Router A/B v1.

## Router Flow

```text
POST /v1/hss/split-derivation
  -> parse and normalize public request shape
  -> verify session JWT and account/project authorization
  -> apply rate limits and request-size limits
  -> check request kind is allowed for the project policy
  -> compute Router request digest
  -> forward A envelope to Deriver A
  -> forward B envelope to Deriver B
  -> wait for encrypted deriver proof-bundle responses
  -> verify public response metadata and transcript digest agreement
  -> return encrypted A/B client proof bundles to the client
```

The Router should persist only public lifecycle state:

- request id
- account id
- session id
- request kind
- protocol version
- transcript nonce hash
- encrypted-envelope digest set
- deriver proof-bundle response hashes
- public transcript digest
- lifecycle status
- timing and error codes

It must not persist decrypted deriver envelopes, A/B protocol payloads, output
shares, HSS driver state, OT state, or joined words.

## Expensive-Work Admission Gate

The Router owns admission for any request that can trigger expensive deriver or
HSS work. This includes registration prepare, key export, recovery, relayer
share refresh, and any future precompute route. The gate runs after cheap
request normalization and policy checks, and before the Router forwards work to
Deriver A or Deriver B.

The gate protects two resources:

- public Router CPU and queue slots
- private deriver CPU, queues, and A/B protocol capacity

The client may request an operation, but it must not supply the gate decision or
gate identity. The Router derives gate context from trusted request metadata:

- source IP or edge-provided client address
- authenticated user/session when present
- org, project, and environment
- request kind
- account or wallet id
- normalized Email OTP email when present
- coarse device/session id when available and privacy-acceptable

For registration prepare, this is the same boundary as refactor-66: early HSS
prepare is useful only when it cannot be spammed before a user completes OTP or
Passkey proof collection.

Initial decisions:

```ts
type ExpensiveWorkGateDecision =
  | {
      kind: 'accepted';
      requestId: string;
    }
  | {
      kind: 'reuse_existing';
      requestId: string;
      existingLifecycleId: string;
    }
  | {
      kind: 'defer';
      reason: 'short_window_saturated' | 'deriver_queue_saturated';
    }
  | {
      kind: 'rejected';
      reason: 'rate_limited' | 'abuse_policy';
      retryAfterMs: number;
    };
```

Operational rules:

- short-window gates should default to one active expensive prepare per key per
  `5s` to `10s` in production
- duplicate normal-user clicks should reuse the current pending lifecycle
- early server precompute must be independently disableable per deployment,
  org/project policy, or incident response state
- saturated deriver queues should return `defer` so the caller can run the
  slower post-auth path or retry later
- rejected requests must stop before Deriver A, Deriver B, or HSS prepare work
- gate records must be short-lived, scoped, single-use where applicable, and
  cleaned up on completion, expiry, or abandon
- diagnostics may record gate timings and decisions, but cannot influence
  transcript binding or proof verification

Disabling early precompute must not disable registration, recovery, export, or
refresh. It changes admission from `accepted` to `defer` for early work, and the
caller continues through the slower authority-verified path where available.

Current implementation note:

- The existing TypeScript router has a narrow registration-prepare rate-limit
  guard under `REGISTRATION_PREPARE_RATE_LIMIT_*`. It injects source-IP context
  server-side, rejects client-supplied gate payloads, and runs before Ed25519
  HSS prepare. The A/B Router should generalize this into the shared
  `ExpensiveWorkGateDecision` lifecycle.

## Direct A/B Coordination Flow

After the Router forwards envelopes, A and B coordinate directly:

```text
Router -> A: aEnvelope, public request metadata
Router -> B: bEnvelope, public request metadata

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

The exact number of A/B messages depends on the chosen two-party HSS/MPC
primitive. The implementation target is:

- ideal: 1 A/B round trip
- acceptable: 2 to 4 A/B round trips
- unacceptable for normal UX: many sequential online rounds

All A/B protocol messages must be authenticated and transcript-bound. They may
contain commitments, masks, OT/correlation messages, encrypted labels, or output
shares. They must not contain raw `y_A`, `y_B`, `tau_A`, `tau_B`,
`y_client_A`, `y_client_B`, `tau_client_A`, `tau_client_B`, joined `d`, joined
`a`, or joined `x_client_base`.

## Output Delivery

At the end of the A/B protocol:

```text
A produces x_client_A and x_relayer_A
B produces x_client_B and x_relayer_B
```

Client-output material:

```text
A -> Client: EncryptToClient(x_client_A package)
B -> Client: EncryptToClient(x_client_B package)
Client opens x_client_base = x_client_A + x_client_B
```

SigningWorker-output material:

```text
A -> SigningWorker: x_relayer_A package
B -> SigningWorker: x_relayer_B package
SigningWorker opens x_relayer_base = x_relayer_A + x_relayer_B
```

The direct A/B -> SigningWorker delivery path is the preferred production
activation profile when latency matters. The payload is still recipient-scoped
ciphertext; Deriver A/B do not receive SigningWorker state, and SigningWorker
does not request A/B derivation work. Router-mediated relay can carry the same
ciphertext in local tests or restricted deployments, with the same
SigningWorker verification and receipt rules.

If the Router aggregates responses, it aggregates ciphertext only:

```ts
type RouterSplitDerivationResponse = {
  requestId: string;
  protocolVersion: string;
  requestKind: RouterSplitDerivationRequest['requestKind'];
  accountId: string;
  sessionId: string;
  transcriptNonce: string;
  publicTranscriptDigest: string;
  aClientPackage: EncryptedClientPackage;
  bClientPackage: EncryptedClientPackage;
};
```

The Router may verify public transcript hashes and deriver signatures, but it
must not be able to decrypt `aClientPackage` or `bClientPackage`.

Strict production delivery uses `RecipientProofBundlePayloadV1` rather than a
joined output package. Each deriver filters its proof batch into a single
recipient-scoped payload before delivery:

```text
Deriver A -> RecipientProofBundlePayloadV1(client, x_client_base, deriver_a)
Deriver B -> RecipientProofBundlePayloadV1(client, x_client_base, deriver_b)
Deriver A -> RecipientProofBundlePayloadV1(SigningWorker, x_relayer_base, deriver_a)
Deriver B -> RecipientProofBundlePayloadV1(SigningWorker, x_relayer_base, deriver_b)
```

The canonical payload binds lifecycle id, producing deriver identity, recipient
role, opened-share kind, recipient identity, transcript digest, and the nested
single-bundle proof batch. The decoder rejects payloads that contain more than
one proof bundle, target the wrong recipient class, or mismatch the enclosed
proof-batch binding. The wire kind is `recipient_proof_bundle`.

`RecipientProofBundleCiphertextV1` encrypts that canonical payload to the final
recipient and is the payload carried by the public
`recipient_proof_bundle` wire kind. Its public header and AAD bind algorithm,
producing deriver identity, recipient role, opened-share kind, recipient
identity, recipient encryption key, transcript digest, payload digest, and
nonce. Cloudflare uses HPKE base mode with X25519, HKDF-SHA256, and AES-256-GCM
for this envelope.

The first deployable strict profile should be:

```text
1. A and B decrypt only their own role envelopes.
2. A and B run the authenticated A/B proof-batch exchange.
3. A and B filter full proof batches into client and SigningWorker
   RecipientProofBundlePayloadV1 values.
4. A and B encrypt each recipient payload to the final recipient key.
5. Router forwards opaque encrypted client bundles in the public response.
6. SigningWorker receives only opaque encrypted SigningWorker bundles and opens
   x_relayer_base locally.
7. Client opens only x_client_base locally.
```

## Normal Signing Flow

The split A/B path is used for derivation-time operations:

- registration
- recovery
- key export
- signing-worker share refresh

Day-to-day signing should use the standalone worker shape:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

The active SigningWorker holds `x_relayer_base`, which is allowed by the target
security model. Normal signing requires Router and the active SigningWorker.
Deriver A and Deriver B participate when derivation, key export, recovery, or
signing-worker share refresh is requested.

## Failure Model

The Router can:

- deny service
- drop or delay messages
- send stale envelopes
- route to the wrong deriver
- replay old requests
- return incomplete responses

The protocol must turn those failures into detectable aborts. The Router should
not be able to learn protected secrets or silently rewrite a successful
derivation.

A or B can:

- deny service
- abort the A/B protocol
- send malformed protocol messages
- attempt transcript confusion
- attempt to make the other party or client accept a bad output

This architecture primarily targets joined-state exclusion. Strong active
malicious correctness requires additional checks, commitments, proofs, or
verifying-share bindings.

## Transcript Binding

Every deriver must verify that its decrypted envelope and A/B protocol messages
bind to the same transcript:

- `protocolVersion`
- `requestKind`
- `accountId`
- `sessionId`
- `requestId`
- `transcriptNonce`
- `expiresAtMs`
- client ephemeral public key
- deriver role
- peer deriver identity
- SigningWorker identity
- Router request digest
- public account verifying key or intended account id binding

Deriver responses must include a deriver signature over the final public
transcript digest.

The client must verify:

- A and B proof bundles bind to the same transcript.
- A proof bundle came from A.
- B proof bundle came from B.
- The proof bundles target the client's ephemeral public key.
- The output kind is client output.
- The request kind and account/session bindings match the original request.

The SigningWorker must verify:

- SigningWorker-output proof bundles bind to the same transcript.
- proof bundles came from the expected A and B identities.
- the output kind is SigningWorker output.
- account and signing-root bindings match the SigningWorker session.

## Cloudflare Deployment Shape

Recommended initial deployment:

```text
Router Worker: public endpoint, auth, policy, rate limits
Deriver A Worker: private/internal derivation endpoint
Deriver B Worker: private/internal endpoint
SigningWorker Worker: private/internal normal-signing endpoint
```

The first deployment keeps normal signing on
`Client -> Router -> SigningWorker -> Router -> Client`. Deriver A and Deriver B
stay in the setup/export/recovery/refresh path.

For stronger operational separation, A and B can live in separate Cloudflare
accounts and communicate over authenticated HTTPS. That adds real network
latency but improves independence.

For lower latency, same-account Service Bindings can connect Workers with very
low overhead. That improves performance but weakens the independent-account
trust boundary. Use this only if the security target accepts one Cloudflare
account as the operational boundary.

## Cloudflare Adapter Boundary

Router A/B should use Cloudflare Durable Objects only through role-specific
adapter bindings. Durable Objects provide Cloudflare-native persistence,
single-object atomicity, replay/idempotency coordination, and operationally
simple local state. They are not a security boundary against a compromised
Worker that is already allowed to access the binding.

The adapter boundary must preserve the same role separation as the local SQLite
host-store checks:

```text
Router Worker:
  allowed Durable Object scopes:
    router replay/idempotency state
    router public lifecycle state
  allowed deriver-envelope HPKE private keys:
    none
  allowed A/B peer signing keys:
    none
  allowed A/B peer verifying keys:
    optional public config only
  forbidden Durable Object scopes:
    Deriver A sealed root shares
    Deriver B sealed root shares
    SigningWorker activation state
  forbidden deriver-envelope HPKE private keys:
    Deriver A deriver-envelope private key
    Deriver B deriver-envelope private key
  forbidden A/B peer signing keys:
    Deriver A peer-message signing key
    Deriver B peer-message signing key

Deriver A Worker:
  allowed Durable Object scopes:
    Deriver A sealed root shares
  allowed deriver-envelope HPKE private keys:
    Deriver A deriver-envelope private key
  allowed A/B peer signing keys:
    Deriver A peer-message signing key
  allowed A/B peer verifying keys:
    Deriver A and Deriver B peer-message verifying keys
  forbidden Durable Object scopes:
    Deriver B sealed root shares
    SigningWorker activation state
    Router replay state
  forbidden deriver-envelope HPKE private keys:
    Deriver B deriver-envelope private key
  forbidden A/B peer signing keys:
    Deriver B peer-message signing key

Deriver B Worker:
  allowed Durable Object scopes:
    Deriver B sealed root shares
  allowed deriver-envelope HPKE private keys:
    Deriver B deriver-envelope private key
  allowed A/B peer signing keys:
    Deriver B peer-message signing key
  allowed A/B peer verifying keys:
    Deriver A and Deriver B peer-message verifying keys
  forbidden Durable Object scopes:
    Deriver A sealed root shares
    SigningWorker activation state
    Router replay state
  forbidden deriver-envelope HPKE private keys:
    Deriver A deriver-envelope private key
  forbidden A/B peer signing keys:
    Deriver A peer-message signing key

SigningWorker Worker:
  allowed Durable Object scopes:
    SigningWorker activation state
  allowed deriver-envelope HPKE private keys:
    none
  allowed A/B peer signing keys:
    none
  allowed A/B peer verifying keys:
    optional public config only
  forbidden Durable Object scopes:
    Deriver A sealed root shares
    Deriver B sealed root shares
    Router replay state
  forbidden deriver-envelope HPKE private keys:
    Deriver A deriver-envelope private key
    Deriver B deriver-envelope private key
  forbidden A/B peer signing keys:
    Deriver A peer-message signing key
    Deriver B peer-message signing key
```

For the first same-account prototype, these can be separate bindings in one
Cloudflare account:

```text
ROUTER_REPLAY_DO
ROUTER_LIFECYCLE_DO
DERIVER_A_ROOT_SHARE_DO
DERIVER_B_ROOT_SHARE_DO
SIGNING_WORKER_OUTPUT_DO
DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY
DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY
DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY
DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY
DERIVER_A_PEER_SIGNING_KEY
DERIVER_B_PEER_SIGNING_KEY
DERIVER_A_PEER_VERIFYING_KEY_HEX
DERIVER_B_PEER_VERIFYING_KEY_HEX
```

For the stronger multi-account deployment, each account should own only the
bindings it needs:

```text
Router account:
  ROUTER_REPLAY_DO
  ROUTER_LIFECYCLE_DO

Deriver A account:
  DERIVER_A_ROOT_SHARE_DO
  DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY
  DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY
  DERIVER_A_PEER_SIGNING_KEY
  DERIVER_A_PEER_VERIFYING_KEY_HEX
  DERIVER_B_PEER_VERIFYING_KEY_HEX

Deriver B account:
  DERIVER_B_ROOT_SHARE_DO
  DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY
  DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY
  DERIVER_B_PEER_SIGNING_KEY
  DERIVER_A_PEER_VERIFYING_KEY_HEX
  DERIVER_B_PEER_VERIFYING_KEY_HEX

SigningWorker account:
  SIGNING_WORKER_OUTPUT_DO
  SIGNING_WORKER_PUBLIC_KEY
```

Deriver-envelope HPKE private keys and A/B peer-message signing keys are
Cloudflare Secret bindings. Deriver-envelope HPKE public keys and A/B
peer-message verifying keys are public config. The typed startup parser
receives only public descriptors and public verifying-key bytes:

```text
DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING=DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY
DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH=envelope-hpke-key-epoch-a
DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY=x25519:<64 lowercase hex chars>
DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING=DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY
DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH=envelope-hpke-key-epoch-b
DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY=x25519:<64 lowercase hex chars>
DERIVER_A_PEER_SIGNING_KEY_BINDING=DERIVER_A_PEER_SIGNING_KEY
DERIVER_A_PEER_SIGNING_KEY_EPOCH=key-epoch-a
DERIVER_B_PEER_SIGNING_KEY_BINDING=DERIVER_B_PEER_SIGNING_KEY
DERIVER_B_PEER_SIGNING_KEY_EPOCH=key-epoch-b
DERIVER_A_PEER_VERIFYING_KEY_HEX=<64 lowercase hex chars>
DERIVER_B_PEER_VERIFYING_KEY_HEX=<64 lowercase hex chars>
```

`workers-rs` startup validation checks the configured Secret binding exists,
without loading the key into startup diagnostics. Deriver A startup rejects any
Deriver B envelope-key or peer-signing-key descriptor. Deriver B startup rejects
any Deriver A envelope-key or peer-signing-key descriptor. Router startup rejects
both role-local key classes.

The Durable Object request protocol should use small explicit operations rather
than generic key/value access in Router A/B adapters:

```text
root_share.has {
  signerSetId,
  signerRole,
  rootShareEpoch
}

root_share.startup_metadata {
  signerSetId,
  signerRole,
  rootShareEpoch
}

signing_worker_output.activate {
  transcriptDigest,
  signingWorkerIdentity,
  rootShareEpoch,
  packageDigest
}

router_replay.reserve {
  requestId,
  transcriptDigest,
  expiresAtMs
}
```

Deriver startup must fail closed if the role-specific root-share Durable Object
binding is missing, points at the wrong storage scope, lacks the expected
deriver-set id, lacks the expected root-share epoch, or returns a deriver role
that differs from the Worker role. Router startup must fail if it receives any
deriver root-share or SigningWorker activation binding.

The first `router-ab-cloudflare` crate should pin this boundary with typed
binding descriptors, role-specific startup configs, and validation tests before
adding `workers-rs` request handlers. The later `workers-rs` layer should be a
thin adapter from `worker::Env` and Service Bindings into those typed configs
and the existing `router-ab-core` host traits.

## Production A/B Orchestration Decision

Strict server-blind production uses recipient-side combine. A and B return only
recipient-scoped proof-batch material: the client receives only `x_client_base`
proof bundles, and the standalone SigningWorker receives only `x_relayer_base`
proof bundles. Each recipient combines its own output locally. Router may relay
opaque bundles, but it must not decrypt them or combine recipient outputs.

The decrypted delivery unit is `RecipientProofBundlePayloadV1`, and the public
wire payload for `WireMessageKindV1::RecipientProofBundle` is
`RecipientProofBundleCiphertextV1`. The decrypted payload is a deriver-produced,
recipient-scoped proof-batch wrapper. It must contain exactly one proof bundle
whose binding matches the declared recipient role, opened-share kind,
recipient identity, transcript digest, and producing deriver identity. Router
adapters may route or store the encrypted envelope bytes; combine authority
stays with the final recipient.

Alternative shapes remain documented for deployment profiles with weaker or
different tradeoffs:

- **Encrypted rendezvous:** A and B post peer bundles into a transcript-scoped
  rendezvous, such as a Durable Object, while encrypting each bundle to the
  final recipient. This preserves Router opacity and gives Cloudflare-native
  coordination. It adds timeout, replay, cleanup, and
  equivocation handling.
- **Deriver-side combine:** A and B exchange proof batches and a deriver produces
  final output material. This is the simplest route shape and matches the
  current preloaded test handler. It weakens the strict server-blind invariant
  unless the combiner runs inside a separately trusted boundary.

Implementation note for v1 strict delivery: an A-to-B or B-to-A peer message is
not enough for the recipient deriver to produce its own proof batch. The
recipient deriver also needs its own Router-to-deriver encrypted envelope,
role-envelope AAD, request-context digest, root-share metadata, and root-share
wire. Router therefore dispatches independently to A and B, and the strict
Router response path requires both deriver proof-bundle responses before
returning client bundles or activating SigningWorker bundles. Transcript-scoped
rendezvous remains
future hardening work.

Release gate:

- The strict production route must expose recipient-scoped proof-batch delivery,
  not deriver-side output packaging.
- The public wire payload must be `RecipientProofBundleCiphertextV1` or a later
  encrypted version, and the decrypted payload must preserve the same
  one-recipient invariant.
- The client path must reject any SigningWorker-output proof bundle.
- The SigningWorker path must reject any client-output proof bundle.
- Any deriver-side combine path must be labeled as a weaker deployment profile
  and kept out of the strict server-blind release gate.

## Operational Roadmap

The protocol should be designed as separate trust domains from day one, even
when the first deployment runs entirely inside one Cloudflare account. That
keeps the initial implementation cheap and simple while preserving a path to
stronger operational separation.

### Stage 1: Single Cloudflare Account Prototype

```text
Cloudflare account 1:
  Router Worker
  Deriver A Worker
  Deriver B Worker
  SigningWorker Worker
  same-account Service Bindings
```

This stage optimizes for development speed, low latency, and operational
simplicity. It should validate:

- role-specific encrypted envelopes
- Router opacity
- A-only and B-only plaintext boundaries
- direct A/B protocol behavior
- client-output encryption
- SigningWorker-output activation
- setup/export/refresh latency
- normal signing latency through Router plus SigningWorker

Even in this stage, the Router must see only ciphertext and public metadata.
Deriver A and Deriver B must use the same role-specific APIs that a future
multi-account or multi-cloud deployment would use.

### Stage 2: Separate Cloudflare Accounts

```text
Cloudflare account 1:
  Router Worker

Cloudflare account 2:
  Deriver A Worker

Cloudflare account 3:
  Deriver B Worker

Cloudflare account 4:
  SigningWorker Worker
```

This stage increases operational separation while keeping the same provider and
deployment model. This stage adds:

- separate Cloudflare account credentials
- separate deploy tokens
- separate secrets and deriver keys
- separate logs and alerting
- authenticated HTTPS between Router, A, and B
- stronger blast-radius reduction for control-plane compromise

The protocol should not change at this stage. The transport changes from
same-account Service Bindings to authenticated cross-account HTTPS, and the
deriver identity registry should pin the expected public keys for A, B, Router,
and the standalone SigningWorker.

### Stage 3: Multi-Cloud TEE Derivers

```text
Cloudflare:
  Router Worker
  SigningWorker Worker

AWS:
  Deriver A on Nitro Enclave-backed service

Google Cloud:
  Deriver B on Confidential VM/service
```

This stage adds provider diversity and hardware-backed execution boundaries for
the split deriver roles. It should bind deriver identity to attestation evidence:

```text
deriver role
provider
attested measurement
signing key
protocol version
deployment epoch
```

Client and Router policy should verify that A and B envelopes are encrypted to
keys associated with acceptable attested measurements. A/B protocol messages
should also bind the peer's attested identity into the transcript.

The security benefit is layered:

- Cloudflare compromise alone cannot read A or B plaintext.
- AWS compromise of A alone cannot reconstruct joined sensitive state.
- Google Cloud compromise of B alone cannot reconstruct joined sensitive state.
- A single deriver TEE compromise exposes only that deriver's split role.
- The protocol still prevents any one deriver from opening joined `d`, `a`, or
  `x_client_base`.

### Promotion Criteria

Move from Stage 1 to Stage 2 after:

- Router opacity tests and source guards are passing.
- A/B role-boundary tests are passing.
- setup/export/refresh latency is acceptable.
- normal signing remains close to the single-SigningWorker path.
- key rotation and deriver identity pinning are implemented.

Move from Stage 2 to Stage 3 after:

- deriver identity is already transcript-bound.
- attestation evidence can be verified and pinned.
- deployment epochs and rollback policy are defined.
- incident response can rotate either deriver independently.
- the added latency and operational complexity are justified by customer or
  threat-model requirements.

## Local Development Simulation

Local development should simulate the split trust domains before any Cloudflare
deployment. The first useful shape is four local services plus local durable
state:

```text
localhost:8787  Router
localhost:8788  Deriver A
localhost:8789  Deriver B
localhost:8790  SigningWorker
local Postgres  signing-root metadata and sealed-share records
```

Each service should run as its own process with its own environment file and
role-specific secrets:

```text
router.env:
  ROUTER_SIGNING_KEY
  DERIVER_A_URL
  DERIVER_B_URL
  SIGNING_WORKER_URL
  no share decrypt keys
  no deriver-envelope HPKE private keys

deriver-a.env:
  DERIVER_ROLE=A
  DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:<64 lowercase hex chars>
  DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY_BINDING=DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY
  DERIVER_A_ENVELOPE_HPKE_KEY_EPOCH=envelope-hpke-key-epoch-a
  DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY=x25519:<64 lowercase hex chars>
  DERIVER_A_PEER_SIGNING_KEY
  DERIVER_A_PEER_SIGNING_KEY_EPOCH
  SIGNING_ROOT_SHARE_A_KEK
  DERIVER_B_URL

deriver-b.env:
  DERIVER_ROLE=B
  DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY=hpke-x25519-private-v1:<64 lowercase hex chars>
  DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY_BINDING=DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY
  DERIVER_B_ENVELOPE_HPKE_KEY_EPOCH=envelope-hpke-key-epoch-b
  DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY=x25519:<64 lowercase hex chars>
  DERIVER_B_PEER_SIGNING_KEY
  DERIVER_B_PEER_SIGNING_KEY_EPOCH
  SIGNING_ROOT_SHARE_B_KEK
  DERIVER_A_URL

signing-worker.env:
  SIGNING_WORKER_ROLE=active
  SIGNING_WORKER_OUTPUT_STORAGE
  SIGNING_WORKER_PUBLIC_KEY
```

Local HTTP is acceptable for the first simulation. The important property is
process, key, role, and type separation. The Router should exercise the same
opaque forwarding behavior locally that it will use with Service Bindings or
cross-account HTTPS in production.

### Local Boundary Simulation

The first local milestone should validate the architecture before the final A/B
cryptographic primitive exists:

- seed local Postgres with dev signing-root metadata and role-specific sealed
  share records
- run Router, Deriver A, Deriver B, and SigningWorker as separate processes
- generate deterministic dev output shares from transcript-bound test vectors
- send one client request to the Router containing encrypted A and B envelopes
- have Router forward opaque envelopes without decrypting them
- have A and B decrypt only their own envelopes
- have A and B coordinate directly over local HTTP
- return encrypted client-output proof bundles through the Router
- deliver SigningWorker-output proof bundles only to the local SigningWorker
- assert that the client opens only `x_client_base`
- assert that the SigningWorker opens only `x_relayer_base`

This milestone should include negative tests for Router plaintext access,
wrong-role payloads, transcript mismatch, replay, expiry, and output-kind
confusion.

### Local Cryptographic Simulation

After the boundary simulation is stable, replace deterministic test-vector
outputs with the real derivation pieces:

- threshold-PRF partial evaluation or the selected split root derivation
- split `y_relayer` and `tau_relayer` material
- direct A/B HSS derivation protocol
- client-output encryption to the client's ephemeral key
- SigningWorker-output delivery to the active SigningWorker
- address and public-key parity tests before and after root-share refresh

The local cryptographic simulation must preserve the same invariant as
production:

```text
Router never decrypts deriver envelopes.
A never receives B plaintext.
B never receives A plaintext.
No local service materializes joined d, a, or x_client_base.
Normal signing uses Router plus one SigningWorker.
```

#### HSS Adapter Boundary

`router-ab-core` should not take a direct dependency on `ed25519-hss` for the
first local parity step. Core owns the Router/A/B transcript, recipient-scoped
proof bundles, role envelopes, and source guards. HSS execution should enter
through a narrow adapter boundary so the core service code never imports joined
HSS driver state or reference expansion helpers.

Initial local parity should live in `router-ab-dev` or a test-only adapter that
can depend on `ed25519-hss`. That adapter may run committed HSS fixtures and
compare public outputs, but it must receive only role-scoped inputs and
recipient-opened outputs:

- client side opens only `x_client_base` proof bundles
- SigningWorker opens only `x_relayer_base` proof bundles
- Router never sees opened output material
- Deriver A/B never receive joined `y_relayer`, joined `tau_relayer`, joined
  `d`, joined `a`, or joined `x_client_base`
- HSS fixture/reference helpers remain outside Router, Deriver A/B, and
  SigningWorker service modules

The production HSS integration can later replace the dev adapter with a
platform-neutral Rust adapter, but the release gate is the same: address and
public-key parity must pass without moving joined HSS state into
`router-ab-core` service code.

### Local Tooling

Current local smoke commands:

```text
dev:router-ab-seed-sqlite
dev:router-ab-signer
```

`dev:router-ab-seed-sqlite` should:

- create the local SQLite schema
- seed or verify signing-root metadata
- seed or verify role-specific sealed-share records
- print row counts and deriver roles from read-back verification
- verify Deriver A and Deriver B startup share availability through the local
  host-store boundary

`dev:router-ab-signer` should:

- allocate service ports
- write or load service-specific dev env files
- start Router, Deriver A, Deriver B, and SigningWorker
- print the Router URL as the only client-facing endpoint

The script should fail closed if Router has any share decrypt key, if Deriver A
has B-only keys, if Deriver B has A-only keys, or if required transcript-binding
configuration is missing.

## Rust/Wasm Implementation Architecture

The implementation should put the protocol-critical code and A/B deriver logic
in platform-agnostic Rust. Cloudflare integration should be a thin
`workers-rs` adapter around that core. The goal is to get Rust's type system,
memory-safety defaults, better constant-time ergonomics, shared native/Wasm test
vectors, compatibility with non-Cloudflare hosts, and a future path toward
Verus-style formal verification.

Preferred split:

```text
pure Rust crates:
  protocol types
  role-specific state machines
  transcript hashing and binding
  encrypted envelope framing
  threshold-PRF integration
  A/B HSS derivation protocol
  client-output and SigningWorker-output package validation

platform-agnostic deriver engines:
  Deriver A engine
  Deriver B engine
  SigningWorker activation engine
  host traits for clock, randomness, storage, keys, transport, and audit

workers-rs wrappers:
  Router Worker HTTP entrypoint
  Deriver A Worker HTTP entrypoint
  Deriver B Worker HTTP entrypoint
  SigningWorker Worker HTTP entrypoint
  Cloudflare Env bindings
  fetch/service-binding transport adapters
  response mapping

TypeScript:
  optional build/test harness glue
  optional host implementation using the same canonical wire protocol
  optional Wasm/npm consumer of the Rust protocol core
```

Router, Deriver A, Deriver B, and SigningWorker may all be Rust Workers. The
protocol boundary should still use portable request/response envelopes rather
than Cloudflare-specific object RPC:

```text
Router -> Deriver A: request carrying encrypted A envelope
Router -> Deriver B: request carrying encrypted B envelope
A <-> B: request carrying transcript-bound protocol messages
Router -> SigningWorker: request carrying SigningWorker-output package
```

That keeps the same core usable across:

- local localhost simulation
- same-account Cloudflare Service Bindings
- cross-account Cloudflare HTTPS
- future AWS Nitro or Google Cloud Confidential deriver services

### Platform-Agnostic Deriver Engines

Deriver A and Deriver B should be ordinary Rust engines that know nothing about
Cloudflare, HTTP frameworks, environment variables, service bindings, or
TypeScript runtimes.

The core shape should be:

```rust
pub struct DeriverEngine<R, H> {
    role: R,
    host: H,
}

impl<R, H> DeriverEngine<R, H>
where
    R: DeriverRole,
    H: DeriverHost,
{
    pub async fn handle_envelope(
        &self,
        input: DeriverEnvelopeRequest,
    ) -> Result<DeriverEnvelopeResponse, DeriverError> {
        // role-specific protocol logic
    }
}
```

The host boundary should be a small set of traits:

```rust
pub trait DeriverHost:
    Clock
    + Csprng
    + DeriverKeyStore
    + SigningRootShareStore
    + PeerTransport
    + AuditSink
{
}
```

The core engine should depend on canonical protocol inputs and host traits. It
should not read environment variables, create HTTP responses, access Cloudflare
bindings directly, or choose transport URLs.

The Cloudflare adapter supplies a host implementation:

```rust
pub struct CloudflareDeriverHost {
    env: worker::Env,
}
```

An Axum, Nitro, GCP, AWS, Node, or TypeScript deployment can use the same model
by implementing the same wire protocol or by calling the Rust core through a
Wasm/npm package.

### Wire Protocol Compatibility

Inter-service APIs should be stable canonical messages, not Cloudflare object
RPC method calls:

```text
Router -> A: DeriverARequestBytes
Router -> B: DeriverBRequestBytes
A <-> B: AbProtocolMessageBytes
A/B -> Router: DeriverResponseBytes
Router -> SigningWorker: SigningWorkerActivationBytes
```

The outer HTTP body may be JSON for product ergonomics, but transcript hashes
must bind canonical inner bytes. Acceptable encodings include CBOR, Borsh,
postcard, or a custom versioned encoding with fixed field ordering and length
rules.

### Crate Layout

Router A/B uses three crates. Keep the design modular inside these crates, and
split out more crates only when dependency boundaries or module size require
it.

```text
crates/router-ab-core
  pure Rust derivation and service protocol core
  selected mpc_threshold_prf_v1 derivation backend
  split-root comparison/prototype material
  transcript, envelope, lifecycle, wire, host-trait, and local simulation modules
  vectors, measurement gates, specs, and formal-verification scaffolding

crates/router-ab-dev
  local database-driver adapters
  SQLite seed and smoke binaries
  development-only persistence verification

crates/router-ab-cloudflare
  workers-rs adapters
  Env parsing and binding validation
  Durable Object operation execution
  Service Binding/fetch transport

crates/threshold-prf
  threshold-PRF primitives and vectors

crates/ed25519-hss
  HSS derivation and signing primitives
```

Optional later package:

```text
packages/router-ab-wasm
  wasm-bindgen/npm package for TypeScript hosts
```

`router-ab-core` must remain platform-neutral and avoid Cloudflare APIs,
filesystem APIs, ambient time, ambient randomness, database drivers, and broad
async dependencies. Boundary adapters inject time, randomness, peer identities,
transport, and storage.

`router-ab-cloudflare` should do only boundary work:

- convert `worker::Request` into canonical protocol input
- parse `worker::Env` into a `CloudflareDeriverHost`
- call platform-agnostic engines
- convert protocol output into `worker::Response`
- map service bindings or fetch into `PeerTransport`
- map Cloudflare secrets/storage into key and share stores

The adapter should not contain HSS derivation logic, threshold-PRF logic,
output-opening logic, or transcript construction beyond invoking the shared
core.

Suggested folder structure:

```text
crates/router-ab-core/
  Cargo.toml
  src/
    lib.rs
    derivation/
      mod.rs
      candidate_mpc_prf.rs
      candidate_mpc_prf_threshold_backend.rs
      context.rs
      diagnostics.rs
      envelope.rs
      evidence.rs
      leakage.rs
      material.rs
      scope.rs
      state_machine.rs
      transcript.rs
      vectors.rs
      wire/
        mod.rs
    protocol/
      mod.rs
      envelope.rs
      error.rs
      gate.rs
      identity.rs
      lifecycle.rs
      local.rs
      output.rs
      payload.rs
      vectors.rs
      wire.rs
      engine/
        mod.rs
        host.rs
        router.rs
        deriver_a.rs
        deriver_b.rs
        signing_worker.rs
    bin/
      dev_router_ab_signer.rs
      emit_contract_vectors.rs
      emit_payload_vectors.rs
      emit_wire_vectors.rs

  benches/
    derivation_candidates.rs
  fixtures/
    derivation/
    protocol/
  specs/
  formal-verification/
  tests/
    *_tests.rs

crates/router-ab-dev/
  Cargo.toml
  src/
    lib.rs
    bin/
      dev_seed_router_ab_sqlite.rs
  tests/
    sqlite_seed.rs

crates/router-ab-cloudflare/
  Cargo.toml
  src/
    lib.rs
    durable_object.rs
```

### Verification Path

Keep the protocol core friendly to later formal verification:

- represent roles as distinct types, not strings
- represent lifecycle states as enums with role-specific variants
- make output kinds explicit and unforgeable at the type level
- keep transcript construction deterministic and canonical
- keep parsing and normalization at boundaries
- avoid global mutable state
- isolate cryptographic primitive calls behind narrow traits
- minimize `unsafe`

Initial Verus targets should be state-machine and boundary invariants:

- Router cannot construct deriver plaintext.
- A-only input cannot enter B-only state.
- B-only input cannot enter A-only state.
- client-output proof bundles cannot be accepted as relayer output.
- relayer-output proof bundles cannot be accepted as client output.
- every accepted output binds to the transcript, role, account, session, and
  request kind.

### Bundle Size And Startup Budget

Rust/Wasm Workers are compatible with Cloudflare, but binary size becomes a
deployment constraint. The Worker should track:

- compressed Worker size
- uncompressed Worker size
- `startup_time_ms` from Wrangler upload/deploy
- CPU time for setup/export/refresh
- CPU time for normal signing

Cloudflare's current documented limits are:

```text
Worker size after gzip:
  Free: 3 MB
  Paid: 10 MB

Worker size before gzip:
  64 MB

Worker startup time:
  1 second

Memory per isolate:
  128 MB
```

The startup limit applies to parsing and executing global scope. Larger bundles
and expensive top-level initialization increase startup time, so Rust Workers
must avoid doing protocol setup, key derivation, large table generation, or
schema construction in global scope.

Use these rules:

- compile with release size optimizations
- use `wasm-opt`
- keep Router, Deriver A, Deriver B, and SigningWorker as separate Workers so
  each bundle carries only its deployment role's code
- avoid large dependency graphs in Router
- initialize Wasm modules and static data minimally
- put expensive derivation inside request handlers
- run `wrangler deploy --dry-run --outdir bundled` and record gzip size
- record `startup_time_ms` on every release candidate

Startup punishment is workload-specific. Treat the target as:

```text
excellent: < 100 ms startup_time_ms
acceptable: 100-300 ms startup_time_ms
risky: 300-700 ms startup_time_ms
unacceptable: approaching 1000 ms
```

The exact value must be measured with the built bundles. A small Rust/Wasm
protocol Worker may start quickly; a large bundle with broad dependencies,
large static tables, or expensive global initialization can fail Cloudflare's
startup validation.

Current optimized strict Worker artifacts, captured June 13, 2026:

```text
commands:
  pnpm -C crates/router-ab-cloudflare measure:strict-workers
  pnpm -C crates/router-ab-cloudflare dry-run:router
  pnpm -C crates/router-ab-cloudflare dry-run:signer-a
  pnpm -C crates/router-ab-cloudflare dry-run:signer-b
  pnpm -C crates/router-ab-cloudflare dry-run:signing-worker

profile:
  worker-build 0.8.4 release
  wasm-opt@130 through worker-build
  wrangler 4.40.3 deploy --dry-run
  deployment-shaped per-role Wrangler configs with Durable Object and Service
  Binding entries

optimized worker-build wasm:
  strict-worker-entrypoint                 combined role dispatch  1,910,324 bytes  gzip 677,044 bytes
  strict-worker-router-entrypoint          Router                  1,533,785 bytes  gzip 521,835 bytes
  strict-worker-signer-a-entrypoint        Deriver A               1,563,499 bytes  gzip 560,554 bytes
  strict-worker-signer-b-entrypoint        Deriver B               1,563,491 bytes  gzip 560,546 bytes
  strict-worker-signing-worker-entrypoint  SigningWorker           1,428,715 bytes  gzip 499,797 bytes

optimized worker-build total package:
  combined role dispatch  1,944,766 bytes  gzip 685,010 bytes
  Router                  1,567,475 bytes  gzip 529,584 bytes
  Deriver A               1,597,441 bytes  gzip 568,398 bytes
  Deriver B               1,597,433 bytes  gzip 568,390 bytes
  SigningWorker           1,461,905 bytes  gzip 507,425 bytes

wrangler dry-run Total Upload:
  Router                  1549.11 KiB  gzip 520.00 KiB
  Deriver A               1578.71 KiB  gzip 557.66 KiB
  Deriver B               1578.70 KiB  gzip 557.62 KiB
  SigningWorker           1445.60 KiB  gzip 497.99 KiB
```

These are below Cloudflare's gzip size limit. Startup evidence is resolved in
the deployment evidence record. The current Wrangler files include DO classes,
migrations, and Service Bindings; production still needs real verifying-key
values, Cloudflare secrets under the configured secret binding names, and
route/account selection.

## Latency Expectations

Setup/export latency is roughly:

```text
client RTT to Router
+ Router auth/rate-limit work
+ parallel Router calls to A and B
+ A/B protocol round trips
+ response aggregation
```

The A/B protocol dominates latency. The design should batch messages and avoid
many sequential network turns.

Current native Router adapter CPU baseline, captured June 12, 2026:

```text
command:
  cargo bench --manifest-path crates/router-ab-cloudflare/Cargo.toml \
    --bench router_latency -- \
    --sample-size 10 --warm-up-time 0.1 --measurement-time 0.2

profile:
  native aarch64-apple-darwin Criterion smoke pass
  Router admission-provider derivation
  Router replay/lifecycle plan execution
  simulated A/B coordination via repeated JSON and canonical wire passes
  no Cloudflare runtime, Service Binding, or network latency

latency:
  1 simulated A/B round trip   62.882 us median
  2 simulated A/B round trips  82.568 us median
  3 simulated A/B round trips 102.72 us median
  4 simulated A/B round trips 123.85 us median
```

Normal signing latency is roughly:

```text
client RTT to Router
+ Router auth/rate-limit work
+ one SigningWorker call
+ signing compute
```

Normal signing should stay close to the current single-SigningWorker behavior.

## Type And Boundary Requirements

Make invalid states unrepresentable at the TypeScript and Rust boundaries.

Route/domain types should distinguish:

- public Router request metadata
- opaque encrypted A envelope
- opaque encrypted B envelope
- decrypted A-only deriver input
- decrypted B-only deriver input
- A/B protocol messages
- encrypted client-output proof bundle
- relayer-output proof bundle
- public transcript metadata

Production Router code must not import types that can decode deriver plaintext or
joined HSS state.

Production Deriver A code must not accept B-only plaintext types.

Production Deriver B code must not accept A-only plaintext types.

Production relayer code may accept only relayer-output proof bundles and the
opened `x_relayer_base`.

## Source Guards

Add source guards or type fixtures that fail when:

- Router production code imports HSS executor joined-state types.
- Router production code imports deriver plaintext envelope types.
- Deriver A routes accept B plaintext input.
- Deriver B routes accept A plaintext input.
- Any production route accepts `DdhHssSharedWord`, evaluator driver state, joined
  projector inputs, or raw joined client/server roots.
- Logs include protocol payload fields rather than hashes and public metadata.
- Client-output proof bundles can be sent to the relayer in plaintext.
- Relayer-output proof bundles can be sent to the client as relayer roots.

## Refactor-66 Carry-Forward Baseline

`docs/refactor-66-optimize-registration-2.md` is closed as the current
registration baseline. Router A/B should carry forward the stable parts and
avoid rebuilding the broader refactor-66 prepared-registration lifecycle in the
current TypeScript/server route model.

Retained baseline pieces:

- narrow server-side `/wallets/register/prepare` admission gate before HSS
  prepare
- Email OTP Ed25519 session-persistence tail deferral
- early Google Email OTP host-origin prepare handle
- registration benchmark matrix and rejection notes
- abuse tests proving rejected repeated prepare attempts do not trigger
  unbounded HSS work

Router A/B must preserve these design lessons:

- Expensive-work admission must happen before deriver/HSS work and derive its
  context from trusted Router metadata, never client JSON.
- Early prepare/precompute must use an explicit scoped handle that binds auth
  method, wallet/account, rp id, deriver mode, intent digest, and protocol
  context.
- Prepared work must be short-lived, replay-protected, and single-use.
- Under load, the Router can defer early prepare and fall back to the slower
  authority-verified path.
- Diagnostics stay observational and must cover browser-visible total, SDK
  visible total, post-auth visible total, hidden prepare work, deriver queue wait,
  HSS prepare/respond/finalize, and client artifact construction.

Current retained benchmark anchors:

- Email OTP session-persistence deferral run `20260611-082802Z`: Email OTP SDK
  p50 improved by about `1.15s`, with session persistence around `2ms` p50.
- Google Email OTP host-origin early prepare run `20260611-120433Z`: browser
  p50 `1115ms`, SDK p50 `1041ms`, and `walletRegisterPrepareWaitMs` p50 `0ms`.
- Confirmation run `20260611-121716Z`: browser p50 `1141ms`, SDK p50
  `1069ms`, and `walletRegisterPrepareWaitMs` p50 `0ms`.

## Implementation Plan

Implementation order:

1. Complete the spec gates that can block architecture: split derivation
   comparison, leakage analysis requirements, transcript binding, and Level C
   claim language.
2. Build `router-ab-core` first: derivation backend, protocol types,
   lifecycle state, wire vectors, source guards, host traits, and invariant
   notes.
3. Add the local Router/A/B simulation on top of those protocol types.
4. Add Cloudflare Router, Deriver A, Deriver B, and SigningWorker adapters after
   the local boundary tests prove role separation, replay handling, and
   output-kind separation.

Current completed work:

- `crates/router-ab-core` is scaffolded for the split-derivation
  primitive comparison.
- Candidate A, MPC threshold PRF, has Router/A/B purpose binding,
  `threshold-prf` compatibility, native crypto-path tests, vectors, leakage
  analysis, and native benchmark evidence.
- Candidate B, split root derivation, has typed adapter scaffolding, vectors,
  leakage analysis, real `HashToScalarSha512V1` derivation, scalar-share
  combine tests, and native benchmark evidence.
- Phase 6 measurement gates are typed in
  `candidate_measurement_gate_report_v1()`.
- Phase 0A side-by-side primitive decision evidence is recorded in
  [phase-0a-decision-record.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-core/specs/phase-0a-decision-record.md).
- Phase 0A selected `mpc_threshold_prf_v1` for production. The split-root
  candidate remains comparison/prototype material until its root-generation,
  anti-bias, refresh, and address-verification questions are resolved.
- `crates/router-ab-core` now also owns the service-level protocol modules,
  including typed expensive-work gate contexts, decisions, principals, and
  registration prepare handles.
- Product-level recovery is mapped to primitive `export` while staying distinct
  at Router policy and lifecycle boundaries.
- `crates/router-ab-core` now has initial lifecycle states, encrypted
  deriver-envelope wrappers, canonical wire-message wrappers, platform-agnostic
  engine wrappers, host traits, and source guards against platform imports.
- Initial wire-message canonical encoding and digest helpers are implemented
  with versioned, length-prefixed field order.
- Cross-host wire-vector fixtures are committed for Router-to-A, Router-to-B,
  A-to-B, B-to-A, and recipient-proof-bundle delivery messages.
- Role-specific client-output and SigningWorker-output proof-bundle types are
  implemented with fixed recipient/opened-share semantics.
- Deriver identity, deriver key epoch, selected SigningWorker identity, v1 all(2)
  deriver-set, and role-envelope assignment types are implemented.
- Exact service payload structs are implemented for Router-to-deriver, A/B peer
  messages, and recipient-proof-bundle delivery.
- Canonical byte encoders, digest helpers, and committed payload fixtures are
  implemented for the exact inner payload structs.
- Exact role-envelope AAD fields, canonical AAD bytes, digest helpers, and
  expiry checks are implemented for encrypted deriver-envelope framing.
- Initial Verus-friendly invariant notes are written for role separation,
  A/B peer direction, output-kind separation, transcript binding, deriver-set
  policy, and host boundaries.
- Authority-verified fallback and normal-signing scopes are modeled separately
  from early prepare and A/B derivation setup.
- Phase 2 local boundary groundwork is started with typed Router, Deriver A,
  Deriver B, and SigningWorker endpoint descriptors, service-specific local
  binding guards, transport-neutral env snapshots, deterministic
  transcript-bound dev output proof bundles, and route-checked local transport
  envelopes, plus deterministic in-process local handlers for Router dispatch,
  deriver proof-bundle responses, A/B peer messages, and SigningWorker activation
  delivery.
  Local startup configs now pair each handler with its validated role-specific
  env snapshot, and the in-process service stack can run the deterministic
  local ceremony from those startup configs. The typed local HTTP boundary and
  `dev:router-ab-signer` smoke command now exercise one client-to-Router
  request through Router, Deriver A, Deriver B, and SigningWorker, including local
  expiry and replay checks.
- Follow-up adapter refactor
  [docs/refactor-67-router-ab-threshold-prf-adapter.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/refactor-67-router-ab-threshold-prf-adapter.md)
  is written and started.
- `router-ab-core` now exposes an initial production
  `mpc_threshold_prf_v1` backend boundary over `threshold-prf`, including a
  Router/A/B-owned signing-root-share wire wrapper, deriver proof-bundle
  evaluation, proof verification, and recipient-side verified combine.
- `threshold-prf` no longer enables `rand_core/getrandom` at the library layer,
  so the production backend dependency builds for both `wasm32-unknown-unknown`
  and `wasm32-wasip1` with explicit RNG injection.
- Focused backend tests now cover client-output combine, client/relayer output
  separation, wrong deriver-share role, malformed share wire, invalid DLEQ proof,
  transcript mismatch, non-deriver role, wrong root epoch, duplicate deriver role,
  wrong recipient, and mixed-purpose combine rejection.
- Candidate A backend vectors are frozen in the generated contract corpus for
  registration, export, and refresh across client and relayer outputs, including
  partial wires, commitments, proofs, verified-combine outputs, and rejection
  cases.
- Local Router/A/B negative tests now cover wrong deriver-role requests at
  deriver handlers, peer messages presented as Router deriver proof-bundle
  responses, and wrong-recipient proof bundles presented as SigningWorker
  activation material.
- `router-ab-core` now has a transport-neutral local persistence seed model
  for signing-root metadata and role-specific sealed-share records, with
  validation for deriver set, root-share epoch, deriver roles, distinct deriver
  ids, storage keys, commitments, and sealed-share length.
- Local persistence seeds now produce validated parameterized SQL seed plans
  for Postgres and SQLite, with fixed bind ordering for root metadata,
  Deriver A sealed shares, and Deriver B sealed shares.
- `router-ab-core` now exposes a driver-neutral local SQL execution
  harness with typed receipts, so local Postgres or SQLite adapters can execute
  the seed plan without adding database drivers to the protocol crate.
- `crates/router-ab-dev` now provides a concrete SQLite seed adapter,
  schema creation, idempotent seed execution, read-back verification, and the
  `dev:router-ab-seed-sqlite` smoke command.
- `crates/router-ab-dev` now implements the protocol
  `SigningRootShareStore` boundary over seeded SQLite and exposes fail-closed
  startup checks for Deriver A and Deriver B root-share availability.
- The Router A/B Cloudflare adapter boundary is defined with Durable Object
  storage scopes, role-specific namespace visibility, and fail-closed startup
  rules. `crates/router-ab-cloudflare` is scaffolded with typed binding
  descriptors and constructor tests for Router, Deriver A, Deriver B,
  SigningWorker, and deriver root-share startup checks.
- `crates/router-ab-cloudflare` now parses role-specific Cloudflare Env-reader
  input into typed binding descriptors, trims required values, rejects missing
  or empty required keys, and rejects forbidden Durable Object key families for
  Router, Deriver A, Deriver B, and SigningWorker.
- `crates/router-ab-cloudflare` now has an optional `workers-rs` feature with a
  pinned `worker = 0.8.4` bridge. The Worker bridge requires Rust 1.88 or newer
  because the current Workers SDK dependency graph includes `wasm-streams`
  0.6.x. `CloudflareWorkerEnvReaderV1` reads real `worker::Env` vars, then
  `parse_cloudflare_worker_bindings_from_worker_env_v1` checks that the
  configured Durable Object namespaces and service bindings are present in the
  runtime Env before startup descriptors are accepted.
- `crates/router-ab-cloudflare` now defines the explicit Router A/B Durable
  Object operation grammar, typed call descriptors, storage-key derivation,
  typed response validation, and a feature-gated `workers-rs` executor that
  posts typed operation JSON to the configured Durable Object stub by name.
- `crates/router-ab-cloudflare` now has a platform-neutral Durable Object
  operation handler and in-memory storage harness. The handler enforces
  operation scope, root-share startup metadata lookup, request-id replay
  reservation, public lifecycle state persistence, and idempotent
  SigningWorker-owned relayer-output activation.
- The Durable Object storage handler now has a feature-gated `workers-rs`
  fetch wrapper that rejects non-POST and wrong-path requests, parses the typed
  operation body, maps the configured Durable Object scope to the expected
  Worker role, and stores responses through Cloudflare `Storage`.
- `crates/router-ab-cloudflare` now has an initial thin Router Worker runtime
  context. It parses/validates Router startup bindings and can construct only
  Router-scoped Durable Object calls for replay reservation and public
  lifecycle state persistence.
- `router-ab-core` now defines `PublicRouterRequestV1`, a transport-neutral
  public request boundary that validates lifecycle scope, deriver-set identity,
  selected relayer, expiry, nonce, and role-specific encrypted envelopes before
  producing canonical Router-to-Deriver A and Router-to-Deriver B wire messages.
- `crates/router-ab-cloudflare` now normalizes a validated public Router
  request plus trusted server-derived admission data into a
  `CloudflareRouterPublicAdmissionPlanV1`. The plan applies the gate decision
  to lifecycle state, reserves replay state, and only includes deriver wire
  messages for accepted or reuse-existing decisions.
- `crates/router-ab-cloudflare` now has a feature-gated `workers-rs` public
  Router handler for `POST /v1/hss/split-derivation`. It reserves replay state,
  persists gate-applied public lifecycle state, forwards opaque role-specific
  deriver wire messages over Cloudflare Service Bindings only after admission,
  and aggregates transcript-bound deriver proof-bundle responses.
- `crates/router-ab-cloudflare` now has strict Deriver A and Deriver B
  private wrappers plus runtime contexts, with SigningWorker activation calls
  split out of Deriver A.
- `crates/router-ab-cloudflare` now derives
  `CloudflareRouterTrustedAdmissionV1` from trusted Router metadata and
  Router-owned project policy, abuse, and quota check results. The derivation
  validates work kind, account id, and session id against the normalized public
  request before deriver forwarding can be planned.
- `crates/router-ab-cloudflare` now verifies the public Router boundary with
  typed tests for auth context binding, project policy rejection, abuse
  throttling, quota saturation, request expiry, and replay reservation before
  deriver forwarding.
- `crates/router-ab-cloudflare` now has a transport-neutral public Router plan
  executor for route-level tests. Rejected admission persists replay/lifecycle
  state without calling deriver transports, and replayed requests stop before
  lifecycle persistence and deriver forwarding.
- `crates/router-ab-cloudflare` now has Durable Object storage-surface tests
  proving Router lifecycle persistence serializes public lifecycle state while
  replay persistence carries only request id, expiry, and request digest
  material.
- `crates/router-ab-cloudflare` now has a preloaded synchronous deriver host
  that implements the current core `DeriverHost` trait set after async
  Cloudflare adapter code has loaded time, root-share metadata, peer responses,
  and randomness.
- `crates/router-ab-cloudflare` now has typed deriver-host preload input, a
  native-tested preload builder, and feature-gated `workers-rs` functions that
  load deriver-local root-share metadata from Durable Objects, capture Worker
  time, and fill bounded random buffers through Web Crypto-backed
  `getrandom`.
- `crates/router-ab-cloudflare` now has direct A/B peer endpoint validation,
  thin `workers-rs` peer fetch wrappers, and a Service Binding executor for
  `DeriverAToDeriverB` and `DeriverBToDeriverA` messages with transcript-bound
  opposite-direction responses.
- `crates/router-ab-cloudflare` now has a peer-request preload input and
  feature-gated `workers-rs` deriver-host preload functions that execute direct
  A/B Service Binding calls before loading root metadata and randomness into
  `CloudflarePreloadedDeriverHostV1`.
- `router-ab-core` now decodes canonical Router-to-deriver payload bytes back
  into typed payloads, and the Cloudflare private deriver endpoint rejects
  malformed payloads, wrong deriver branches, and payload/wire transcript
  mismatches before handler execution.
- `router-ab-core` now validates Router-to-deriver lifecycle/deriver-set/relayer
  binding plus deriver assignment identity before decoded payloads can reach a
  deriver handler.
- Local Deriver A/B handlers now decode Router-to-deriver payloads and reject
  malformed payloads, transcript mismatches, wrong branches, and valid
  same-role payloads addressed to a different local deriver identity before
  producing output.
- `crates/router-ab-core/specs/envelopes-and-delivery.md` now specifies the
  `deriver_input` plaintext contract for the next decryption slice: public
  derivation metadata and output instructions only, strict decoding, no joined
  state fields, and deriver-local root-share loading after plaintext checks.
- `router-ab-core` now implements `DeriverInputPlaintextV1` with canonical
  bytes, a strict decoder, Candidate A-only validation, duplicate output
  rejection, selected-relayer binding, and trailing-byte rejection.
- `router-ab-core` now validates decoded deriver-input plaintext against the
  Router-to-deriver payload before deriver work can use it, including lifecycle,
  deriver-set, deriver identity, relayer identity, transcript, Router request
  digest, AAD digest, and local root-share epoch binding.
- `router-ab-core` now has a Router boundary source guard preventing
  Router-facing protocol modules from importing deriver-input plaintext decoder
  APIs.
- Local Deriver A/B handlers now pass through a deterministic typed
  deriver-envelope decryptor boundary before output generation. The local
  decryptor returns `DeriverInputPlaintextV1`, then the handler validates it
  against the Router-to-deriver payload, local Router request digest, and
  deriver-local root-share epoch.
- `crates/router-ab-cloudflare` now has a post-decrypt deriver-input plaintext
  validation boundary. Cloudflare deriver adapters can feed decrypted bytes into
  `decode_and_validate_cloudflare_signer_input_plaintext_v1`, which decodes
  `DeriverInputPlaintextV1` and binds it to the Router payload, Router request
  digest, AAD digest, root metadata role, deriver identity, and root-share
  epoch.
- `crates/router-ab-cloudflare` now has a narrow validated private deriver
  request boundary for production deriver engines. Future engine wrappers receive
  `CloudflareValidatedDeriverPrivateRequestV1`, which contains only the
  role-checked Router-to-deriver payload and already-validated
  `DeriverInputPlaintextV1`; response transcript validation still runs after the
  handler returns.
- `router-ab-core` now keeps `DeriverInputPlaintextV1` limited to typed
  derivation metadata and recipient-scoped output instructions. Forbidden
  joined-state exposure is enforced with typed output-request validation and
  source guards, rather than runtime substring checks on public identifiers.
- `router-ab-core` now has a required authenticated A/B peer-message envelope:
  canonical bytes-to-sign, sender and recipient deriver identity binding,
  transcript binding, payload digest binding, signature scheme, and signature
  bytes. `crates/router-ab-cloudflare` decodes those peer payloads and rejects
  wire messages whose embedded direction, transcript, or authentication digest
  does not match the route.
- `router-ab-core` now exposes an Ed25519 verifier for authenticated A/B peer
  messages. The verifier checks the canonical bytes-to-sign against a
  sender-bound verifying key and rejects wrong-key signatures.
- Cloudflare deriver-host preload guards now require direct A/B peer requests
  and responses to decode as authenticated peer-message payloads before
  synchronous engine code can consume them.
- `router-ab-core` deriver hosts now expose deriver-bound Ed25519 verifying-key
  access. `crates/router-ab-cloudflare` carries trusted verifying keys into
  preloaded deriver hosts, verifies preloaded peer requests/responses before
  synchronous engine code can consume them, and verifies parsed direct A/B peer
  requests before the handler runs.
- `router-ab-core` now has an Ed25519 signing helper for A/B peer-message
  authentication input, and local-dev outbound A/B peer messages use
  deterministic local signing keys to produce real signatures.
- `crates/router-ab-cloudflare` now has role-local A/B peer signing-key
  descriptors, Worker Env binding validation, and a `workers-rs` helper that
  loads a Cloudflare Secret Ed25519 seed, signs the canonical peer-message
  authentication input, and clears the raw seed bytes after use.
- `crates/router-ab-cloudflare` now runs the committed core wire vectors
  through the Worker JSON boundary and the committed typed payload vectors
  through Cloudflare Router-to-deriver and direct A/B peer route validation.
- `crates/router-ab-cloudflare` now binds preloaded deriver hosts to an
  expected deriver role and rejects Durable Object root-share metadata for the
  opposite deriver before constructing the host.
- `crates/router-ab-cloudflare` now has a feature-gated pre-split
  `workers-rs` wrapper for SigningWorker-owned activation. It executes the typed
  relayer-output Durable Object call and accepts only the activation receipt
  response branch.
- `router-ab-core` now has a local Router opacity regression test: Router
  forwards kind-correct opaque deriver payload bytes without decoding them, and
  malformed payloads are rejected only at the deriver boundary.
- `router-ab-core` now has the strict recipient proof-bundle delivery unit:
  `RecipientProofBundlePayloadV1` plus
  `WireMessageKindV1::RecipientProofBundle`. The payload carries exactly one
  recipient-scoped proof bundle and rejects wrong recipient role, opened-share
  kind, deriver identity, or transcript bindings before combine.
- `router-ab-core` now has `RecipientProofBundleCiphertextV1` plus a
  `RecipientProofBundleEncryptorV1` adapter boundary. The ciphertext header and
  AAD bind the producing deriver identity, and core exposes a
  `recipient_proof_bundle` wire-message builder for final-recipient delivery.
  `router-ab-cloudflare` implements
  `CloudflareHpkeRecipientProofBundleEncryptorV1` and verifies HPKE round-trip
  opening back into the typed proof-bundle payload.
- `crates/router-ab-cloudflare` now has typed strict proof-bundle containers for
  private deriver proof-bundle response, Router client-bundle aggregation, and
  SigningWorker activation. These containers decode only public ciphertext
  envelope metadata and validate deriver identity, recipient role, opened-share
  kind, recipient identity, recipient encryption key, and transcript digest
  against the Router payload.
- `crates/router-ab-cloudflare` now wires those strict containers through
  feature-gated `workers-rs` entrypoints: private deriver proof-bundle routes,
  strict Router service aggregation, and the SigningWorker proof-bundle
  activation route. The strict deriver engine wrapper signs and validates the
  local proof batch, then returns only the local deriver's encrypted client and
  SigningWorker proof bundles.
- `crates/router-ab-cloudflare` now has an optional
  `strict-worker-entrypoint` feature that builds a `cdylib` Worker artifact,
  parses `ROUTER_AB_WORKER_ROLE` and `ROUTER_AB_ROUTE_PROFILE`, dispatches the
  strict Router proof-bundle route from a bearer JWT plus Router-owned
  admission stores, and dispatches typed deriver-private bootstrap bodies through
  the deriver-host preload, decrypt, and strict proof-bundle path.
- `router-ab-core` now carries public `root_share_epoch` in
  `LifecycleScopeV1`, canonical Router-to-deriver payload bytes, public Router
  request bytes, and committed payload vectors. This is the first concrete step
  toward the non-circular deriver-envelope AAD and transcript digest redesign.
- `router-ab-core` now has `PublicRouterRequestContextV1` and
  `request_context_digest()`, a pre-envelope digest over public request context
  that excludes transcript digest, role-envelope AAD digests, and ciphertext.
  Deriver-input plaintext fixtures now bind this context digest, while Router replay
  tests continue to use the full request digest.
- `router-ab-core` now has a pre-envelope derivation transcript path:
  `PublicRouterRequestContextV1::derivation_transcript_digest()` computes the
  transcript digest before deriver-envelope encryption, `PublicRouterRequestV1`
  rejects mismatched transcript digests, and derivation `TranscriptBinding`
  no longer carries encrypted-envelope digests.
- `router-ab-core` now separates transcript metadata from envelope assignment
  metadata. `RouterTranscriptMetadataV1` carries public derivation context, and
  `RouterEnvelopeDigestSetV1` carries A/B encrypted-envelope digests used only
  for Router-to-deriver assignment validation.
- `PublicRouterRequestV1::router_replay_digest()` now names the full-envelope
  Router replay/idempotency digest explicitly. Cloudflare Router admission uses
  it when reserving replay state, while deriver AAD/plaintext continues to use
  the pre-envelope request-context digest.
- `crates/router-ab-cloudflare` now has
  `CloudflareDeriverPrivateBootstrapRequestV1`, which carries the private
  Router-to-deriver wire message, typed `RoleEnvelopeAadV1`, and pre-envelope
  request-context digest. It also has `CloudflareDeriverHostPreloadPlanV1`,
  which derives deriver-set id, root-share epoch, local deriver identity,
  transcript digest, and request-context digest from that bootstrap body before
  host preload.
- The strict Worker deriver routes now parse typed deriver-private bootstrap
  bodies, validate role-envelope AAD, derive the deriver-host preload plan, and
  validate trusted A/B peer verifying keys from role-local Worker config.
- Router A/B v1 strict proof-bundle delivery now uses independent Router
  dispatch to Deriver A and Deriver B. Each deriver produces only local
  recipient-scoped proof bundles; Router aggregation requires both deriver
  responses for liveness.
- The strict Worker Deriver A and Deriver B private routes now invoke the
  deriver-host preload, deriver-envelope decrypt, root-share wire, peer signing
  key, and strict proof-bundle handler path end to end.
- Role-specific release Wasm, `wasm-opt`, and Wrangler dry-run packaging size
  measurements are recorded. Cloudflare runtime `startup_time_ms` and
  production deployment evidence still need release-candidate data.
- `crates/router-ab-cloudflare` now exposes workers-rs Durable Object classes
  for Router replay, Router lifecycle, Router project policy, Router quota,
  Router abuse, Deriver A root-share, SigningWorker activation, and Deriver B
  root-share storage. The per-role Wrangler configs now declare those classes,
  migrations, Service Bindings, role-local Env names, and secret binding-name
  variables.
- `crates/router-ab-cloudflare` now has a focused Wasm vector test script:
  `pnpm -C crates/router-ab-cloudflare test:wasm-vectors`. It runs the
  committed wire and payload vectors under Node with the workers-rs Router
  entrypoint feature enabled.
- `crates/router-ab-cloudflare` now has a typed Router admission-provider
  boundary. Auth/session, project policy, abuse, and quota providers return
  `CloudflareRouterAdmissionProviderOutputV1`; Router derives
  `CloudflareRouterTrustedAdmissionV1` from that provider-owned output.
- `crates/router-ab-cloudflare` now has a composite Router admission-provider
  chain. The chain accepts already verified JWT/session claims, evaluates an
  explicit allowed-work-kind project policy, applies abuse/quota decisions, and
  lets the Router runtime build admission plans directly from the provider.
- Router admission-provider Cloudflare Env descriptors now exist for JWT
  issuer/audience/JWKS URL plus Router-only project-policy, quota, and abuse
  Durable Object bindings. Deriver roles reject these admission Env keys.
- Router admission now has typed adapter interfaces for strict bearer-token
  parsing, JWT verification, JWT-backed session derivation, and Router-owned
  store-backed project-policy, quota, and abuse providers.
- Router admission-store bindings now build typed Durable Object calls for
  project-policy, quota, and abuse evaluation, and workers-rs helpers unwrap
  those typed responses after Durable Object execution.
- Router Worker startup bindings now require the JWT verifier config plus
  Router project-policy, quota, and abuse Durable Object bindings. The strict
  Router entrypoint fails closed if those admission bindings are absent.
- `crates/router-ab-cloudflare` now has a Router-runtime admission-store call
  plan plus a workers-rs helper that derives trusted admission from a verified
  JWT session and Router-owned project-policy, quota, and abuse Durable Object
  responses.
- `crates/router-ab-cloudflare` now has an EdDSA/Ed25519-only JWKS JWT
  verifier with strict issuer, audience, expiry, not-before, request session,
  and account binding checks. The strict Router public route now accepts only
  `PublicRouterRequestV1` in the body and derives trusted admission from the
  Bearer token plus Router-owned admission stores.
- A Cloudflare source guard now fails if the strict Router route reintroduces a
  trusted-admission bootstrap body or bypasses the Bearer-JWT admission helper.
- Client-to-deriver envelope encryption is clarified as a public-key HPKE model:
  clients encrypt A and B envelopes to Deriver A and Deriver B public envelope
  keys, bind the selected key epoch into the request transcript/AAD, and allow
  daily key rotation with an overlap window no longer than request TTL plus
  retry grace.
- `router-ab-core` now has a strict deriver-envelope HPKE payload wrapper that
  binds recipient role, key epoch, recipient public key, AAD digest,
  encapsulated X25519 key, and ciphertext/tag bytes before platform-specific
  decrypt. `router-ab-cloudflare` now has HPKE public envelope-key descriptors,
  role-local private decrypt-key descriptors, Env-reader parsers, forbidden Env
  guards for private key bindings, and pre-decrypt metadata validation.
- `router-ab-cloudflare` now has native Rust deriver-envelope HPKE seal/open
  helpers, a versioned `hpke-x25519-private-v1:` Cloudflare Secret text format
  for private-key bytes, a `workers-rs` HPKE Secret-loading decrypt
  wrapper, and tests for successful open, modified AAD, wrong private key, and
  private-key Secret parsing.
- Strict Deriver A/B Worker startup bindings and decrypt-and-handle paths now
  use the deriver-envelope HPKE decrypt-key descriptor and HPKE open wrapper.
  The previous role-local deriver-envelope AEAD runtime has been removed from
  strict deriver startup and runtime paths.
- `crates/router-ab-cloudflare` now has `benches/router_latency.rs`, which
  records a native CPU baseline for Router admission plus simulated A/B
  coordination over 1, 2, 3, and 4 local round trips.

Immediate next steps:

1. Capture deployed or Wrangler-profiled setup/export and normal-signing
   latency. Native normal-signing hot-path latency is now benchmarked.
2. Capture Cloudflare Worker runtime latency evidence from a deployed or
   wrangler-profiled strict Worker.
3. Replace Wrangler verifying-key placeholders and provision Cloudflare secrets
   for each deriver role before any production deploy.
4. Decide whether JWKS fetch needs per-isolate caching before production load
   tests, or whether the provider/CDN cache is sufficient for the MVP.
5. Keep `split_root_derivation_v1` as comparison/prototype material until its
   unresolved gates justify revisiting it.

### Phase 0A: Spec Gates

- [x] Compare MPC threshold-PRF-to-shares and new split root derivation with
      vectors, leakage analysis, and performance probes.
  - [x] Scaffold `crates/router-ab-core` as the primitive comparison
        crate.
  - [x] Add Candidate A typed adapter, vectors, leakage analysis, and native
        cryptographic-path benchmark evidence.
  - [x] Add Candidate B typed adapter, vectors, leakage analysis, and adapter
        benchmark evidence.
  - [x] Implement Candidate B's real `HashToScalar` and scalar-combine path.
  - [x] Capture Candidate B native cryptographic-path benchmark evidence.
  - [x] Record final side-by-side decision evidence.
- [x] Choose the split derivation primitive only after the comparison is
      recorded.
  - [x] Select `mpc_threshold_prf_v1` for the production path.
- [x] Specify the role-separated HSS API boundary and forbid joined-state APIs
      in production Router A/B paths.
- [x] Lock the Minimum Level C initial claim language.
- [x] Record strong output correctness as later hardening work with extension
      points in transcript and output-package formats.
- [x] Define the `DerivationCeremony` state machine and request-kind scopes.
- [x] Define the minimum transcript binding fields for deriver identity and
      rotation.
- [x] Define typed redacted diagnostics and source-guard requirements.
- [x] Define release gates and test vectors for local simulation, Cloudflare
      prototype, real split derivation, and production root rotation.

### Phase 0: Adopt Refactor-66 Baseline

- [x] Record the retained refactor-66 benchmark anchors in Router A/B benchmark
      docs.
- [x] Port expensive-work gate semantics into `router-ab-core` lifecycle
      types.
- [x] Define accepted, reuse-existing, defer, and rejected gate decisions before
      Cloudflare route work starts.
- [x] Define scoped early prepare/precompute handles for registration setup.
- [x] Preserve the slower authority-verified fallback when early prepare is
      disabled or saturated.
- [x] Keep normal signing unaffected by prepared-registration setup.

### Phase 1: Protocol Types And Invariants

- [x] Create or consolidate the pure Rust protocol crate for role-specific
      protocol types, state machines, transcript binding, envelope framing,
      engines, and host traits.
  - [x] Consolidate primitive and service-level protocol modules into
        `crates/router-ab-core`.
  - [x] Keep derivation code under `src/derivation` and service protocol code
        under `src/protocol`.
  - [x] Add the first service-level gate boundary types to
        `crates/router-ab-core`.
  - [x] Resolve how product-level recovery maps to primitive request kinds.
  - [x] Add initial service-level lifecycle states.
  - [x] Add initial encrypted deriver-envelope wrappers.
  - [x] Add initial canonical wire-message wrappers.
- [x] Keep `router-ab-core` free of Cloudflare APIs, filesystem APIs,
      ambient time, ambient randomness, and transport dependencies.
- [x] Define `router-ab-core/src/protocol/engine` with Router, Deriver A,
      Deriver B, SigningWorker activation, and host-trait modules.
- [x] Define host traits inside `router-ab-core` for clock, randomness,
      deriver keys, signing-root share storage, peer transport, and audit sinks.
- [x] Define canonical request/response bytes for Router-to-A, Router-to-B,
      A-to-B, B-to-A, and recipient-proof-bundle delivery.
  - [x] Add initial versioned, length-prefixed `WireMessageV1` canonical bytes
        and digest helper.
  - [x] Define exact service payload structs for Router-to-deriver, A/B peer
        messages, and recipient-proof-bundle delivery.
  - [x] Add canonical encoders for exact service payload structs.
  - [x] Add committed fixtures for exact service payload structs.
- [x] Add cross-host wire vectors so Rust native, Rust/Wasm, and TypeScript
      hosts can verify the same transcript bytes.
- [x] Define role-specific Router, A, B, client-output, and relayer-output
      types.
- [x] Model Router A/B v1 around a deriver-set and indexed role-envelope shape,
      while enforcing an `all(2)` quorum policy for the first release.
- [x] Define encrypted envelope framing with transcript-bound associated data.
  - [x] Add first role-encrypted envelope wrapper with header and AAD digests.
  - [x] Define exact role-envelope AAD fields and canonical AAD digest helper.
  - [x] Resolve non-circular canonical bytes for deriver-envelope AAD,
        transcript digest, and Router replay digest. - [x] Add public root-share epoch to Router request scope. - [x] Add pre-envelope request-context digest for AAD/plaintext. - [x] Add pre-envelope derivation transcript digest for HSS/output
        bindings. - [x] Keep full-envelope replay digest scoped to Router storage. - [x] Add strict deriver bootstrap body carrying typed AAD from Router.
- [x] Define deriver identities and key rotation rules.
- [x] Add type fixtures rejecting invalid branch combinations.
  - [x] Add constructor tests for invalid gate branches, lifecycle scope,
        deriver-set roles, duplicate deriver ids, envelope role mismatch, and
        output package recipient semantics.
- [x] Add source guards for forbidden imports in Router and deriver code.
- [x] Add initial Verus-friendly invariant notes for role separation,
      output-kind separation, and transcript binding.

### Phase 2: Local Boundary Simulation

- [x] Add local service entrypoints for Router, Deriver A, Deriver B, and
      SigningWorker.
  - [x] Add protocol-level local endpoint descriptors for Router,
        Deriver A, Deriver B, and SigningWorker.
  - [x] Add deterministic in-process local service handlers for those
        entrypoints.
- [x] Add service-specific local env loading with forbidden-key checks.
  - [x] Add transport-neutral local binding validators with role-specific
        forbidden-key checks.
  - [x] Wire validators into a transport-neutral local env snapshot.
  - [x] Wire snapshots into role-checked local service startup configs.
  - [x] Wire startup configs into executable in-process local service startup.
- [x] Add local Postgres or SQLite seeding for signing-root metadata and role-specific
      sealed-share records.
  - [x] Add transport-neutral seed records for signing-root metadata and
        role-specific sealed shares.
  - [x] Wire seed records into a Postgres/SQLite SQL seed plan.
  - [x] Add a driver-neutral local SQL execution harness for the SQL seed plan.
  - [x] Add a concrete SQLite script/driver adapter for the
        SQL seed execution harness.
  - [x] Wire seeded SQLite persistence into local deriver startup or host-store
        checks.
- [x] Add deterministic transcript-bound dev output shares for boundary tests.
- [x] Add local HTTP transport for Router-to-deriver and A-to-B coordination.
  - [x] Add route-checked local transport envelopes for Router-to-deriver,
        A-to-B, B-to-A, and SigningWorker activation delivery.
  - [x] Add executable in-process handlers on top of the checked envelopes.
  - [x] Add typed local HTTP handlers on top of the checked envelopes.
- [x] Add a `dev:router-ab-signer` script that starts the full local stack.
- [x] Add end-to-end local tests that send one client request to the Router and
      verify encrypted A/B package delivery.
- [x] Add negative local Router/A/B tests for wrong-role payloads and
      output-kind confusion.
  - [x] Add in-process local test covering Router dispatch, Deriver A/B
        responses, A/B peer messages, and SigningWorker activation routing.
  - [x] Add in-process local test running the service stack from startup
        configs.
  - [x] Add typed local HTTP test running one client-to-Router request through
        the local service stack.
- [x] Add negative local tests for Router plaintext access, wrong-role payloads,
      replay, expiry, transcript mismatch, and output-kind confusion.
  - [x] Add negative local tests for wrong routes, wrong HTTP path/method, and
        transcript mismatch.
  - [x] Add negative local tests for client request expiry and replayed request
        nonces.
  - [x] Add Router opacity test proving malformed opaque deriver payloads are
        forwarded by Router and rejected at the deriver boundary.

### Phase 3: Router Boundary

- [x] Create `crates/router-ab-cloudflare` with typed Cloudflare Durable Object
      storage scopes, role-specific binding descriptors, and startup-check
      descriptors.
- [x] Add typed Env-reader parsing behind the Cloudflare binding descriptors.
- [x] Add the optional `worker::Env` bridge and real binding-presence checks.
- [x] Add typed Durable Object call execution for replay reservations, Router
      admission lifecycle state, root-share startup checks, and
      SigningWorker-owned relayer-output activation.
- [x] Implement Router Durable Object handler storage for replay reservations
      and Router admission lifecycle state.
      Cloudflare storage now rejects skipped and rewritten Router admission
      lifecycle transitions. Full `DerivationCeremony` persistence remains a
      production release blocker.
- [x] Add the feature-gated `workers-rs` Durable Object fetch/storage wrapper.
- [x] Add the initial thin `workers-rs` Router startup/runtime wrapper around
      validated Router-scoped core types.
- [x] Add the thin `workers-rs` public Router request handler around
      `router-ab-core`.
- [x] Add the public split-derivation route.
- [x] Define the transport-neutral public Router request boundary.
- [x] Parse and normalize public request metadata once into Router-scoped work.
- [x] Verify auth, project policy, quota, abuse controls, expiry, and replay
      window.
- [x] Add typed trusted Router metadata and admission-check derivation for
      auth, project policy, quota, and abuse outcomes.
- [x] Add a typed Router admission-provider boundary that owns auth/session,
      project policy, quota, and abuse checks before trusted admission is
      derived.
- [x] Add a composite Router admission-provider chain with verified JWT/session
      claims, allowed-work-kind project policy, abuse, quota, and runtime plan
      derivation.
- [x] Define Cloudflare Router admission Env descriptors for JWT verifier
      config plus Router-only project-policy, quota, and abuse Durable Object
      bindings.
- [x] Add typed strict bearer-token parsing, JWT verifier, JWT-backed session,
      and store-backed project-policy, quota, and abuse provider adapters.
- [x] Implement the concrete Worker/JWKS JWT verifier and wire stored Router
      admission into the strict public fetch path.
  - [x] Add typed Durable Object operation grammar, storage keys, in-memory
        handler state, workers-rs handler state, tests, and Router Wrangler
        declarations for project-policy, quota, and abuse stores.
  - [x] Add typed admission-store call builders plus workers-rs execution
        helpers for project-policy, quota, and abuse Durable Object responses.
  - [x] Make Router Worker startup/runtime bindings require JWT config and
        Router admission Durable Object bindings.
  - [x] Add a Router-runtime admission-store call plan and workers-rs helper
        that derives trusted admission from verified JWT metadata plus stored
        project-policy, quota, and abuse responses.
  - [x] Implement the concrete Worker/JWKS JWT verifier.
  - [x] Replace trusted-admission bootstrap input on the strict Router public
        route with Router-derived admission from bearer JWT plus store-backed
        project-policy, quota, and abuse providers.
- [x] Add the Router-owned expensive-work admission gate before deriver
      forwarding.
- [x] Derive gate context from trusted Router metadata, never from client
      JSON.
- [x] Implement accepted, reuse-existing, defer, and rejected gate decisions.
- [x] Add route tests proving rejected requests do not reach Deriver A, Deriver B,
      or HSS prepare.
- [x] Forward A/B encrypted envelopes without decrypting them.
- [x] Persist only public lifecycle state and payload hashes.
- [x] Aggregate encrypted client proof bundles into one response.

### Phase 4: Deriver A/B Services

- [x] Implement Deriver A/B Durable Object handler storage for root-share startup
      checks and current SigningWorker activation.
- [x] Add thin `workers-rs` Deriver A and Deriver B wrappers around the
      platform-agnostic deriver engines.
- [x] Add Deriver A, Deriver B, and current SigningWorker runtime contexts
      around validated Cloudflare bindings.
- [x] Add a preloaded synchronous Cloudflare deriver host that implements the
      current core host traits.
- [x] Wire workers-rs async preload from Env, Durable Objects, and randomness
      into the preloaded deriver host.
- [x] Add the direct A/B peer service-binding endpoint.
- [x] Wire direct A/B peer-response preload into the preloaded deriver host.
- [x] Add private A and B deriver endpoints.
- [x] Decrypt only role-specific envelopes.
  - [x] Decode and role-check Router-to-deriver payloads before deriver output.
  - [x] Require payload deriver assignment to match deriver-set and local deriver
        identity.
  - [x] Specify the `deriver_input` plaintext schema and strict rejection rules.
  - [x] Implement the `DeriverInputPlaintextV1` canonical decoder.
  - [x] Validate decoded deriver-input plaintext against Router-to-deriver
        payload, Router request digest, and local root-share epoch.
  - [x] Add a deterministic local deriver-envelope decryptor boundary that
        returns typed deriver input plaintext.
  - [x] Add the Cloudflare post-decrypt deriver-input plaintext validation
        boundary for production adapters.
  - [x] Add deriver-envelope HPKE/X25519 public envelope-key descriptors,
        role-local private decrypt-key descriptors, Env-reader parsers, private
        key visibility guards, and strict public HPKE payload parsing/binding.
  - [x] Add deriver-envelope HPKE/X25519 seal/open helpers, versioned
        private-key Secret parsing, `workers-rs` HPKE decrypt wrapper, and
        native runtime tests for successful open, AAD mismatch, and wrong
        private key.
  - [x] Switch strict Deriver A/B Worker handlers and startup bindings to the
        HPKE/X25519 decrypt path before production release.
  - [x] Remove the obsolete deriver-envelope AEAD parser, Cloudflare key
        descriptors, WebCrypto decrypt helper, tests, docs, and wrangler
        variables after the HPKE strict-worker switch.
  - [x] Add a narrow validated private deriver request boundary for production
        deriver-engine wrappers.
  - [x] Wire the real private deriver engine wrapper through the Cloudflare
        decrypt-then-validate boundary.
    - [x] Promote or add a platform-neutral builder from
          `RouterToSignerPayloadV1` plus `DeriverInputPlaintextV1` into
          `MpcPrfThresholdDeriverBatchInputV1`.
    - [x] Add a production root-share wire source to the Cloudflare deriver host.
      - [x] Add redacted preloaded root-share wire records and a role-local
            host accessor for deterministic production-adapter tests.
      - [x] Add a versioned lower-hex root-share wire secret decoder that
            returns only the redacted role-local preloaded record.
      - [x] Add role-local Cloudflare root-share wire Secret binding
            descriptors and Env parsing.
      - [x] Load the role-local root-share wire from the selected Cloudflare
            Secret binding path, validate it against startup metadata, and
            return only the redacted preloaded record.
      - [x] Wire async Cloudflare deriver-host preload to attach the validated
            role-local root-share wire Secret to the synchronous deriver host.
      - [ ] Add a sealed Durable Object or KMS-backed storage path if
            production rotations need runtime unsealing beyond Cloudflare
            Secret binding rotation.
    - [x] Add Deriver A and Deriver B validated handlers that run
          `DeriverAEngine`/`DeriverBEngine`, authenticate A/B proof-batch
          messages, and use `CloudflareHpkeRecipientProofBundleEncryptorV1`
          for recipient delivery.
      - [x] Promote shared A/B proof-batch delivery so local dev and Cloudflare
            use the same transcript and proof-bundle commitment logic.
      - [x] Add a Cloudflare validated MPC PRF engine bridge that turns a
            decrypt-validated deriver request plus role-local root-share wire
            into a real `DeriverAEngine`/`DeriverBEngine` proof batch.
      - [x] Add shared Cloudflare proof-batch helpers that sign local proof
            batches, verify/decode authenticated peer proof batches, and build
            canonical recipient proof-bundle responses.
      - [x] Add a synchronous Cloudflare validated MPC PRF deriver handler that
            evaluates the local proof batch, signs it for peer verification, and
            returns encrypted recipient proof bundles.
      - [x] Add a testable peer signing-key/request binding check for Worker
            role, deriver identity, and deriver key epoch before loading the
            secret signing key bytes.
      - [x] Wire the workers-rs wrapper to load the role-local peer signing key
            Secret, call the synchronous validated MPC PRF handler, and pass
            `CloudflareHpkeRecipientOutputEncryptorV1` for production delivery.
      - [x] Connect the production private fetch/bootstrap path to
            recipient-scoped MPC PRF proof-batch delivery once the deployable
            Worker entrypoint supplies role-envelope AAD, Router request digest,
            root-share metadata, and root-share wire.
        - [x] Resolve the production A/B orchestration shape before exposing
              this as a deployable deriver route: strict server-blind production
              uses recipient-side combine, and deriver-side combine remains a
              preloaded test or weaker deployment profile.
        - [x] Add core recipient-scoped proof-batch views so client delivery can
              carry only `x_client_base` proof bundles and SigningWorker
              delivery can carry only `x_relayer_base` proof bundles.
        - [x] Add a core one-recipient combine helper that opens exactly one
              requested output binding and rejects missing or mismatched
              recipient proof bundles.
        - [x] Design the live Cloudflare delivery shape for recipient-scoped
              proof bundles: Router-carried opaque bundles encrypted to the
              final recipient, with Durable Object rendezvous deferred until
              timeout/retry pressure justifies it.
          - [x] Add canonical `RecipientProofBundlePayloadV1` and
                `WireMessageKindV1::RecipientProofBundle` for one-recipient
                proof-batch delivery.
          - [x] Add `RecipientProofBundleCiphertextV1`, AAD binding, and
                Cloudflare HPKE encryption for client or active SigningWorker
                recipient keys.
          - [x] Add typed strict Cloudflare private deriver proof-bundle
                response, Router client-bundle aggregation, and
                SigningWorker activation containers around encrypted
                recipient proof-bundle payloads.
          - [x] Wire the strict containers through `workers-rs` private deriver,
                Router aggregation, and SigningWorker activation entrypoints.
          - [x] Add a deployable Worker bootstrap scaffold that chooses the
                strict proof-bundle route profile and dispatches the trusted
                Router route.
          - [x] Add strict private-bootstrap-to-deriver-host preload plan
                derivation before deriver-host execution.
          - [x] Add a deployable trusted A/B verifying-key provider for the
                strict deriver-host preload input.
          - [x] Decide the deployable live peer-coordination shape:
                independent Router dispatch to A and B, with Router
                aggregation requiring both deriver proof-bundle responses for
                liveness.
          - [x] Scope async direct A/B peer coordination to deriver-side combine,
                rendezvous, or later hardening profiles outside v1 strict
                proof-bundle delivery.
          - [x] Wire deployable Deriver A and Deriver B private route
                bootstraps to the deriver-host preload provider.
      - [x] Promote shared MPC PRF recipient-proof-bundle delivery so local dev
            and Cloudflare adapters use the same commitment logic with
            adapter-specific recipient encryption.
      - [x] Specify and bind the selected SigningWorker recipient encryption key
            in the selected SigningWorker identity type, deriver-set canonical
            bytes, and transcript digests for HPKE SigningWorker delivery.
- [x] Verify transcript binding and deriver role.
- [x] Load only deriver-local root material.
- [x] Reject any payload that contains joined state.
  - [x] Strict `DeriverInputPlaintextV1` decoding rejects unknown/trailing
        plaintext bytes.
  - [x] Guard Router-facing protocol modules against deriver plaintext decoder
        imports.
  - [x] Reject Router-to-deriver payloads for the wrong deriver role.
  - [x] Use typed recipient output requests plus source guards for forbidden
        joined-state exposure.
- [x] Add direct A/B mutual authentication.
  - [x] Add a canonical A/B peer authentication input and required signature
        carrier to `AbPeerMessagePayloadV1`.
  - [x] Decode Cloudflare peer payloads before handler execution and reject
        sender/recipient direction, transcript, or authentication-digest
        mismatches.
  - [x] Require authenticated peer-message payloads in Cloudflare deriver-host
        preloaded peer request/response inputs.
  - [x] Add a core Ed25519 verifier for authenticated A/B peer payloads.
  - [x] Extend deriver host key access with trusted deriver verifying keys.
  - [x] Verify Ed25519 peer request signatures before handler execution.
  - [x] Verify preloaded peer request/response signatures before synchronous
        engine execution.
  - [x] Add local peer signing-key access for outbound A/B messages.
  - [x] Add production Cloudflare signing-key loading for outbound A/B
        messages.
  - [x] Run the same wire and payload vectors through Cloudflare adapter
        boundary tests.

### Phase 5: Direct A/B Protocol

- [x] Implement the split derivation primitive selected by Phase 0A.
  - [x] Add the selected `mpc_threshold_prf_v1` deriver batch-evaluation
        backend for all requested deriver outputs.
  - [x] Wire the batch evaluator into platform-agnostic deriver engines.
- [x] Implement A/B protocol message types with transcript-bound signatures.
  - [x] Add a canonical `AbDerivationProofBatchPayloadV1` carrying
        threshold-PRF proof bundles under the authenticated A/B peer envelope.
  - [x] Validate inner proof-batch sender, recipient, transcript, root epoch,
        and proof-bundle bindings against the signed peer envelope.
- [x] Ensure messages carry only protocol-safe material.
  - [x] Add source guards preventing A/B peer payload modules from importing
        combined outputs, root-share wires, or raw secret material.
- [x] Produce A/B shares of client and SigningWorker outputs.
  - [x] Deriver engines produce threshold-PRF proof bundles for both
        `x_client_base` and `x_relayer_base`.
  - [x] Add a deriver-identity-checked builder that signs those proof bundles
        into authenticated A/B peer payloads.
  - [x] Add a recipient-side batch combiner that verifies matching A/B proof
        bundles and produces combined client and relayer output material.
- [x] Keep A/B round trips within the target budget.
  - [x] Record and test the current adapter round-trip profile: one
        Router-facing client request, one Router invocation, one Deriver A
        invocation, one Deriver B invocation, and zero modeled direct A/B
        coordination round trips per ceremony.

### Phase 6: Output Delivery

- [x] Encrypt A and B client-output proof bundles directly to the client
      ephemeral key.
  - [x] Public Router requests now require a client ephemeral public key, and
        the key is bound into the derivation transcript digest and
        Router-to-deriver payload metadata.
  - [x] Recipient proof bundles now carry a typed ciphertext envelope binding
        algorithm, recipient role, opened share kind, recipient identity,
        recipient encryption key, transcript digest, and payload commitment.
  - [x] Recipient-output ciphertext envelopes now expose canonical AEAD
        associated-data bytes for adapter encryption and decryption.
  - [x] Recipient-output plaintext now crosses a narrow
        `RecipientOutputEncryptorV1` adapter boundary, with local deterministic
        output encryption implemented behind that same trait.
  - [x] Add the production recipient-output algorithm identifier
        `hpke_x25519_hkdf_sha256_aes256gcm_v1` and require
        `x25519:<64 lowercase hex chars>` recipient keys for that suite.
  - [x] Evaluate `hpke = "=0.14.0-pre.2"` as the first direct Rust
        dependency candidate for the Cloudflare adapter. Deferred: its
        pre-release transitive graph failed to compile locally in
        `sha3-0.11.0-rc.7`.
  - [x] Select and pin `hpke-ng = "=0.1.0"` with default features disabled.
        Native tests and the `wasm32-unknown-unknown` Cloudflare adapter check
        pass with this dependency graph.
  - [x] Add `CloudflareHpkeRecipientOutputEncryptorV1` behind the existing
        `RecipientOutputEncryptorV1` boundary, with adapter round-trip and
        malformed X25519 key rejection tests.
  - [x] Add an RFC 9180 AES-256-GCM base-mode open vector for
        `hpke_x25519_hkdf_sha256_aes256gcm_v1`, including modified-AAD
        rejection.
  - [x] Add deterministic seal vectors and a Wasm vector pass for
        `hpke_x25519_hkdf_sha256_aes256gcm_v1`.
    - [x] Add a Wasm vector pass proving Cloudflare recipient proof-bundle HPKE
          seal/open works under `wasm32-unknown-unknown` and rejects
          AAD-bound payload-digest drift.
    - [x] Add a native deterministic recipient proof-bundle HPKE seal vector
          using the selected library's low-level RNG seam. Production
          `CloudflareHpkeRecipientProofBundleEncryptorV1` continues to use
          runtime randomness.
  - [x] Replace local placeholder proof-bundle ciphertext with recipient-key
        encryption.
    - [x] `LocalDeterministicRecipientProofBundleEncryptorV1` now encrypts
          canonical recipient proof-bundle payload bytes with a
          recipient-key-bound deterministic local stream envelope and validates
          a local tag at recipient open time.
    - [x] Local SigningWorker activation opens and verifies the encrypted
          SigningWorker proof bundles before issuing an activation receipt; a
          tampered-ciphertext regression now fails at the recipient boundary.
- [x] Production release gate: verify AES-256-GCM constant-time posture for the
      Cloudflare Wasm target before production use. If this cannot be
      established, define a ChaCha20-Poly1305 HPKE suite as a new protocol
      algorithm.
  - [x] Audit the selected dependency posture for `wasm32-unknown-unknown`:
        `hpke-ng = 0.1.0` uses `aes-gcm = 0.10.3`, `aes = 0.8.4`, and
        `ghash/polyval = 0.5/0.6`; the Wasm build selects the AES software
        fixslice backend and POLYVAL `soft32` backend, both documented as
        constant-time portable implementations.
  - [x] Resolve the remaining runtime assumption before production: establish
        that Cloudflare Workers' deployed WebAssembly runtime gives
        constant-time integer multiplication for the selected target, or add a
        new ChaCha20-Poly1305 HPKE algorithm and vectors.
    - [x] Runtime posture resolved in the deployment/security evidence record;
          ChaCha20-Poly1305 fallback is not required for Router A/B v1.
- [x] Deliver SigningWorker-output proof bundles only to the active
      SigningWorker.
  - [x] `CloudflareSigningWorkerRecipientProofBundleActivationRequestV1` is the
        current Cloudflare activation payload name that carries encrypted
        SigningWorker proof bundles. Rename it during the SigningWorker
        slimming refactor.
- [x] Add client-side verification for matching transcript and output kind.
  - [x] Recipient-side combine checks the expected transcript and enforces the
        client `x_client_base` proof-bundle type before opening.
- [x] Add SigningWorker-side verification for matching transcript and output
      kind.
  - [x] Recipient-side combine checks the expected transcript and enforces the
        SigningWorker `x_relayer_base` proof-bundle type before opening.
- [x] Add downgrade rejection for clients requiring split derivation.
  - [x] Public Router requests now carry a required derivation candidate, and
        v1 rejects anything other than `mpc_threshold_prf_v1` before deriver
        payloads are created.

### Phase 6B: MVP Security Boundary Refactor

This phase fixes the audit findings that are part of the lean Router A/B MVP.
The target shape is a narrow `mpc_threshold_prf_v1` flow where Router transports
ciphertext, derivers emit recipient-scoped proof and delivery material, and only
the client or standalone SigningWorker opens the final recipient output.

Refactor principles:

- Keep combined recipient material out of Router, shared service helpers, and
  deriver-response construction.
- Keep local simulation faithful to the production trust boundary.

MVP blockers:

- [x] Remove production exports that return joined recipient output material to
      server-side callers, especially helpers that expose
      `MpcPrfThresholdCombinedOutputV1` outside recipient-local code. The
      joined package-combine helpers were deleted from core output code, and
      Cloudflare no longer exposes the old MPC deriver handler that returned
      joined `DeriverResponse` packages.
- [x] Replace central server-side output packaging with encrypted
      recipient-proof-bundle delivery in the local and Cloudflare deriver paths.
      A and B emit encrypted proof bundles scoped to
      `x_client_base -> client` and `x_relayer_base -> SigningWorker`; Router
      carries only client bundles and SigningWorker activation carries only
      SigningWorker bundles.
- [x] Add recipient-local combine/open APIs for client and SigningWorker callers so
      each recipient can open only its own requested output from delivered proof
      bundles. Core now exposes
      `combine_mpc_prf_recipient_output_from_proof_bundle_payloads_v1`, which
      accepts decrypted Deriver A/B recipient proof-bundle payloads and combines
      only the requested recipient output.
- [x] Update the local ceremony so it mirrors production: Router dispatches
      only, A/B coordinate directly, Router collects encrypted client proof
      bundles, and the SigningWorker accepts only encrypted `x_relayer_base`
      SigningWorker proof bundles. The local Router and shared local stack no
      longer build joined client or SigningWorker output material.
- [x] Tighten Minimum Level C evidence so verification requires the exact
      proof-bundle shape for v1: Deriver A and Deriver B each commit to the
      expected client and SigningWorker recipient proof bundle, empty package
      lists fail, and missing deriver output fails before activation.
- [x] Replace heuristic `"joined"` substring guards in runtime validation with
      typed boundaries or source guards for this path when the recipient-bundle
      delivery refactor makes those runtime checks unnecessary.

Recommended order:

1. [x] Tighten Minimum Level C package-shape verification and add rejection tests
       for missing Deriver A or Deriver B output.
2. [x] Remove central server-side combine/package exports and the old
       Cloudflare deriver-response handler.
3. [x] Rewrite the local ceremony around encrypted recipient-proof-bundle
       delivery.
4. [x] Move recipient output opening behind recipient-local combine APIs.
5. [x] Continue Router admission and Cloudflare Durable Object adapter work.
       SigningWorker Durable Object storage should accept the strict encrypted
       SigningWorker proof-bundle activation request instead of the old joined
       output payload.
   - [x] Replace SigningWorker activation request state that carried the full
         Router-to-deriver payload with a public
         `SigningWorkerActivationContextV1`. The activation context carries
         lifecycle, signer set, public transcript metadata, and transcript
         digest, while omitting deriver envelope assignment/ciphertext.
   - [x] Add a SigningWorker-only recipient combine helper that opens
         `x_relayer_base` from decrypted Deriver A/B proof bundles using the
         public activation context.
   - [x] Add Cloudflare activation validation and source guards proving the
         SigningWorker activation request stores the public activation context,
         not the full Router payload.

### Phase 7: Normal Signing Integration

Architecture update: the target deployment is four dedicated roles:
`Router`, `Deriver A`, `Deriver B`, and `SigningWorker`. Deriver A and Deriver B
are derivation-only. Normal signing flows through
`Client -> Router -> SigningWorker -> Router -> Client`. The pre-split
Cloudflare activation path was transitional scaffolding; new normal-signing
product behavior should use the dedicated SigningWorker boundary.

- [x] Split the pre-split Deriver A relayer-output activation code into a standalone
      SigningWorker `workers-rs` wrapper.
      `crates/router-ab-cloudflare` now has a first-class
      `CloudflareWorkerRoleV1::SigningWorker`, SigningWorker startup bindings,
      a strict SigningWorker entrypoint feature, SigningWorker activation
      fetch handling, and Router service binding validation for the dedicated
      SigningWorker peer. Deriver A no longer owns relayer-output startup
      bindings.
  - [x] Rename active-state and activation types from `Relayer*` to
        `SigningWorker*`.
        Normal-signing scope now binds `signing_worker_id`, core state uses
        `ActiveSigningWorkerStateV1` and
        `RouterToSigningWorkerSigningRequestV1`, and the Cloudflare activation
        and active-state Durable Object API now uses
        `CloudflareSigningWorker*` request/receipt/record names.
  - [x] Move activation Durable Object ownership from Deriver A scopes to
        SigningWorker scopes.
        `CloudflareDurableObjectScopeV1::signing_worker_relayer_output()` is
        visible only to `SigningWorker`, and relayer-output HPKE decrypt-key
        bindings validate only for the SigningWorker role.
  - [x] Keep compatibility only at request/persistence boundaries during the
        rename, then delete the old names.
        The MVP rename is breaking: no legacy aliases or compatibility
        variants were added. The underlying cryptographic output label remains
        `x_relayer_base`/`Role::Relayer` where it is part of the derivation
        protocol vocabulary.
- [x] Store or activate `x_relayer_base` only in SigningWorker state for the
      current Cloudflare SigningWorker implementation.
      Deriver A/Deriver B startup bindings reject SigningWorker relayer-output
      Durable Object bindings and HPKE decrypt-key env, while SigningWorker
      owns activation and active-state lookup calls.
  - [x] SigningWorker Durable Object state stores an activation record
        containing the encrypted SigningWorker proof-bundle activation request,
        SigningWorker-local opened `x_relayer_base` material, and active state.
        The current implementation uses
        `CloudflareSigningWorkerOutputActivationRecordV1`; the storage shape
        matches the dedicated SigningWorker boundary.
  - [x] The active descriptor exposes only account, session, selected
        SigningWorker identity, transcript digest, activation digest, material
        handle, and activation time through `ActiveSigningWorkerStateV1`.
- [x] Keep normal signing on the Router plus active SigningWorker path.
      The Cloudflare Router now has a public normal-signing boundary that
      accepts `NormalSigningRequestV1`, verifies JWT account/session binding,
      and forwards only the normal-signing request to the configured
      SigningWorker service binding. The SigningWorker private route remains
      handler-backed so the product signer owns the actual signature operation.
- [x] Define the normal-signing Router/SigningWorker boundary before
      implementing the route:
  - [x] `NormalSigningRequestV1` and response structs.
        `router-ab-core` now has `NormalSigningRequestV1`,
        `ActiveSigningWorkerStateV1`,
        `RouterToSigningWorkerSigningRequestV1`, and
        `NormalSigningResponseV1`, with tests for expiry, active
        SigningWorker matching, and response-to-request binding. The
        Cloudflare adapter now has a typed SigningWorker forwarding boundary
        and handler trait around these structs.
  - [x] Router admission for normal signing that reuses auth/rate-limit checks
        without invoking A/B derivation stores.
    - [x] MVP Router admission verifies a normal-signing JWT and requires the
          JWT `account_id` and `session_id` to match `NormalSigningScopeV1`
          before forwarding to SigningWorker.
    - [x] MVP Router admission reserves the normal-signing `request_id` and
          request digest in the Router replay Durable Object before forwarding
          to SigningWorker, so repeated or conflicting request ids cannot be
          silently re-signed.
    - [x] Add a dedicated normal-signing policy/quota gate without overloading
          `ExpensiveWorkKindV1`.
          The Cloudflare adapter now has normal-signing-specific trusted
          metadata, admission-store requests, Durable Object operations, and
          Router runtime call builders for project policy, quota, and abuse.
          Normal-signing quota uses a distinct per-account key and returns
          `ShortWindowSaturated` for a different active request instead of
          treating it as lifecycle reuse.
  - [x] Active SigningWorker-state lookup keyed by
        account/session/SigningWorker identity.
    - [x] Dedicated SigningWorker Cloudflare path has
          `CloudflareActiveSigningWorkerStateLookupV1`, `SigningWorkerOutputActiveStateGet`,
          and a fetch wrapper that resolves active state before invoking
          normal-signing logic.
  - [x] Production activation opens encrypted SigningWorker proof bundles into
        SigningWorker-local signing material and persists only the material
        handle plus public activation digests in `ActiveSigningWorkerStateV1`.
    - [x] Dedicated SigningWorker production activation validates the
          recipient HPKE key against the selected worker identity, opens only
          `x_relayer_base -> SigningWorker` proof bundles, stores
          `CloudflareRelayerOutputMaterialRecordV1` inside the activation
          Durable Object, and leaves `ActiveSigningWorkerStateV1` public-only.
  - [x] Router-to-SigningWorker forwarding path.
        The forwarding request struct exists under the SigningWorker name; the
        public Router route now forwards authenticated normal-signing requests
        directly to SigningWorker.
    - [x] Current adapter has
          `CloudflareSigningWorkerNormalSigningHandlerV1`,
          `build_cloudflare_router_to_signing_worker_normal_signing_request_v1`,
          `handle_cloudflare_signing_worker_normal_signing_private_request_v1`,
          `handle_cloudflare_signing_worker_normal_signing_private_fetch_v1`,
          and `execute_cloudflare_signing_worker_normal_signing_service_call_v1`.
    - [x] Current Router-to-worker service-call helper forwards only
          `NormalSigningRequestV1` to the SigningWorker route
          and validates `NormalSigningResponseV1` against the original request.
    - [x] SigningWorker private normal-signing route now materializes active
          state and SigningWorker-local `x_relayer_base` material before the
          handler boundary.
          The Cloudflare adapter added
          `SigningWorkerOutputMaterialGet`,
          `CloudflareSigningWorkerOutputMaterialLookupV1`, and
          `CloudflareSigningWorkerMaterializedNormalSigningRequestV1`, so a
          normal signer receives a validated request plus the matching active
          material record.
    - [ ] Wire the production role-separated Ed25519-HSS normal signer behind
          `CloudflareSigningWorkerNormalSigningHandlerV1`.
          The strict Worker route intentionally remains fail-closed until the
          HSS signing API exists. It must not derive an Ed25519 private key from
          `x_relayer_base` alone.
  - [x] Source guard proving normal-signing routes cannot call A/B derivation
        setup/export handlers for the SigningWorker boundary functions.
- [x] Ensure normal signing routes cannot invoke A/B derivation paths
      accidentally.
- [x] Add operational controls for signing-worker share refresh.
      SigningWorker relayer-output activation now checks the current active
      state before writing a new activation. A refresh for the same
      account/session/SigningWorker may replace active state only when its
      activation timestamp is newer; stale and same-time refresh attempts are
      rejected so active signing material cannot roll back.

Current release status as of 2026-06-14:

- Normal signing has the target production boundary
  `Client -> Router -> SigningWorker -> Router -> Client`, and A/B derivation
  is off the hot path.
- The strict Cloudflare SigningWorker still returns a fail-closed normal-signing
  handler error until the production role-separated Ed25519-HSS signer API is
  wired behind `CloudflareSigningWorkerNormalSigningHandlerV1`.
- Cloudflare Durable Object storage enforces the Router admission lifecycle
  transition (`Requested -> gate/fallback outcome`) and rejects skipped,
  rewritten, or scope-changing writes.
- Full `DerivationCeremony` persistence for
  `Created -> ... -> Activated/Failed/Expired/Abandoned` is still open.
- The manual `deploy-router-ab` workflow runs
  `pnpm -C crates/router-ab-cloudflare assert:release-ready` for
  `operation=deploy`; validation and version upload can still run for evidence.

### Phase 8: Local Cryptographic Simulation

- [x] Replace deterministic dev output shares with the selected split derivation
      primitive.
  - [x] Local in-process ceremonies now convert signed A/B threshold-PRF proof
        batches into recipient-scoped encrypted proof bundles. Router output is
        limited to client bundles, while SigningWorker activation receives only
        SigningWorker bundles.
  - [x] Deriver handlers now emit only authenticated A/B proof-batch peer
        messages. Local Router responses and SigningWorker activation are built
        after both proof batches are validated and split by recipient.
  - [x] Rename local activation package and receipt types from
        `LocalRelayer*` to `LocalSigningWorker*`.
        The local ceremony result now exposes
        `signing_worker_activation` and
        `signing_worker_activation_receipt`, while the cryptographic output
        label remains `x_relayer_base` / `Role::Relayer`.
  - [x] Split the local in-process service stack into four first-class roles:
        Router, Deriver A, Deriver B, and SigningWorker.
        Local service startup now uses `LocalDeriverA*`, `LocalDeriverB*`, and
        `LocalSigningWorker*` types, and `LocalServiceStackV1::new` requires a
        dedicated SigningWorker startup before any ceremony can run.
  - [x] Add the dedicated local deployment parity plan:
        `docs/router-a-b-local-dev.md`. The plan keeps the current
        in-process harness for fast tests and adds a follow-up four-process
        HTTP harness that mirrors Router, Deriver A, Deriver B, and
        SigningWorker deployment boundaries.
- [x] Wire threshold-PRF partial evaluation or the selected split root
      derivation into local A/B services.
  - [x] Replace opaque local A/B peer-message bodies with signed
        threshold-PRF proof-batch peer payloads.
  - [x] Carry or reconstruct the production transcript binding at the local
        deriver boundary, including network id, account public key, Router id,
        client id, and separate encrypted-envelope assignment digests.
        `RouterTranscriptMetadataV1` and `RouterEnvelopeDigestSetV1` now ride
        inside each Router-to-deriver payload, and local deriver proof-batch
        generation rejects reconstructed transcript digest mismatches before
        threshold-PRF evaluation.
  - [x] Update the Router A/B threshold-PRF adapter, tests, and benchmark
        imports to use the fixed `threshold_prf::v1` API after the
        `threshold-prf` t-of-N module split.
- [x] Wire split `y_relayer` and `tau_relayer` material into the local A/B HSS
      derivation protocol.
  - [x] Document the HSS adapter boundary: keep `ed25519-hss` fixture/reference
        execution outside `router-ab-core` service modules, initially in a dev
        or test-only adapter, and require role-scoped inputs plus
        recipient-opened outputs.
  - [x] Add the first `router-ab-dev` HSS split-relayer parity adapter.
        It loads committed `ed25519-hss` fixtures, splits `y_relayer` modulo
        `2^256` and `tau_relayer` modulo Ed25519 `l` into deterministic
        Deriver A/B shares, reconstructs them only inside the dev adapter, runs
        reference expansion, and reports public/commitment evidence.
  - [x] Add a `router-ab-core` source guard proving `ed25519-hss` stays behind
        the `router-ab-dev` adapter boundary.
  - [x] Add role-scoped `router-ab-dev` HSS relayer-input share types and
        verifier APIs. The verifier now accepts explicit Deriver A and Deriver
        B shares, rejects mixed split epochs, redacts raw share debug output,
        and keeps fixture-only construction as a convenience wrapper.
  - [x] Add `router-ab-dev` source-guard coverage proving role-scoped HSS
        relayer-input shares keep raw fields private, do not derive
        serialization, and redact debug output.
  - [x] Add a dev-only recipient output boundary for local HSS evaluation.
        `router-ab-dev` now evaluates explicit Deriver A/B relayer-input
        shares into redacted recipient-scoped `x_client_base -> client` and
        `x_relayer_base -> SigningWorker` base-share outputs with public
        commitment evidence.
  - [x] Scaffold a `router-ab-dev` local ceremony harness that composes the
        core Router/Deriver/SigningWorker in-process ceremony with HSS
        role-scoped parity evidence for the same fixture account public key.
  - [x] Re-enable the composed local HSS ceremony smoke test after the
        concurrent `threshold-prf` t-of-N refactor stabilized local
        signing-root-share wire fixtures. The direct ignored-test probe passed,
        and the smoke now runs in the default `router-ab-dev` HSS parity suite.
- [x] Add local address and public-key parity tests.
  - [x] Add `router-ab-dev` public-key parity tests proving the split-relayer
        fixture adapter reproduces committed `ed25519-hss` public keys from
        recipient-opened `x_client_base` and `x_relayer_base` base shares.
  - [x] Add local address encoding/parity checks for the product account-key
        representation that will gate production root activation.
        `LocalEd25519HssSplitRelayerParityReportV1` now includes the
        `ed25519:<base58 public key>` NEAR key string, and tests decode it back
        to the committed public key bytes.
- [x] Add local root-share refresh tests proving wallet identity is preserved.
  - [x] Add `router-ab-dev` split-epoch refresh parity tests proving rotated
        Deriver A/B `y_relayer` and `tau_relayer` share commitments preserve
        the same committed public key and NEAR `ed25519:<base58>` key string.
- [x] Verify no local process materializes joined `d`, `a`, or
      `x_client_base`.
  - [x] Add a local source guard preventing `src/protocol/local.rs` from
        importing or calling recipient output combine APIs, combined-output
        types, split-root combined outputs, `SecretMaterial32`, or
        `output_material`.
  - [x] Add a local source guard proving Deriver A/B endpoint and service
        structs do not own SigningWorker relayer-output storage, while the
        SigningWorker service struct does not own deriver signer/root-share
        state.
  - [x] Align local SigningWorker activation with production by accepting only
        `SigningWorkerActivationContextV1`, plus source-guard coverage
        preventing the activation method from accepting full Router payloads.

### Phase 9: Validation And Benchmarks

- [x] Add tests for Router opacity.
- [x] Add tests for wrong-role deriver payload rejection.
- [x] Add tests for transcript mismatch, replay, expiry, and wrong relayer.
- [x] Add tests proving no joined state crosses production route boundaries.
  - [x] Add a Cloudflare source guard preventing production adapter code from
        importing or calling recipient-side threshold output combine paths.
  - [x] Add a Cloudflare source guard preventing the strict Router public route
        from accepting caller-supplied trusted admission.
  - [x] Add a Cloudflare source guard preventing SigningWorker activation
        requests from carrying full Router-to-deriver payload state.
  - [x] Refresh Cloudflare root-share test fixtures for the selected
        `threshold-prf` canonical 34-byte signing-root-share wire; the full
        `crates/router-ab-cloudflare --test bindings` suite now passes.
- [x] Add native Rust tests for platform-agnostic deriver engines without
      Cloudflare dependencies.
- [x] Add Wasm tests proving the same canonical wire vectors pass through the
      `workers-rs` adapters.
  - [x] Add `tests/wasm_vector_adapters.rs` and
        `pnpm -C crates/router-ab-cloudflare test:wasm-vectors`.
- [x] Add optional TypeScript compatibility tests that parse and verify the
      canonical wire protocol.
  - [x] Add a Playwright unit test that parses
        `crates/router-ab-core/fixtures/protocol/wire/wire-vectors-v1.json`
        through a boundary parser, recomputes TypeScript canonical wire bytes,
        and verifies the Rust-pinned SHA-256 digests.
- [x] Record compressed and uncompressed release Wasm size for Router,
      Deriver A, and Deriver B before the standalone SigningWorker split.
  - [x] Record combined strict Worker role-dispatch artifact size:
        2,370,450 bytes uncompressed, 671,138 bytes gzip.
  - [x] Record role-specific strict Worker release Wasm sizes:
        Router 1,836,346 bytes uncompressed / 487,682 bytes gzip;
        pre-split Deriver A activation 2,126,483 / 614,303;
        Deriver B 1,990,085 / 577,469.
  - [x] Record Wrangler-bundled and `wasm-opt` sizes for each role:
        Router 1088.52 KiB / gzip 381.52 KiB;
        pre-split Deriver A activation 1340.19 KiB / gzip 497.55 KiB;
        Deriver B 1273.60 KiB / gzip 478.68 KiB.
- [x] Record Wrangler `startup_time_ms` for every Rust/Wasm Worker.
      See Phase 9B for the deploy-time startup latency benchmark checklist.
- [x] Add standalone SigningWorker size rows and remove the embedded
      pre-split Deriver A activation measurement target.
  - [x] Record current blocked state: Wrangler `startup_time_ms` requires
        deployed or Wrangler-profiled role Worker bundles. Wrangler dry-run
        records upload totals, but does not emit `startup_time_ms`.
  - [x] Add standalone SigningWorker measurement tooling and config:
        `measure:strict-workers` now builds `strict-worker-signing-worker-entrypoint`,
        `package.json` has `build:signing-worker` and
        `dry-run:signing-worker`, `wrangler.signing-worker.toml` defines the
        dedicated SigningWorker Worker, and Router wrangler config declares the
        `SIGNING_WORKER` service binding required by startup parsing.
  - [x] Record the actual standalone SigningWorker size row after the
        concurrent `threshold-prf` t-of-N refactor restored workspace
        compilation for the Cloudflare Worker build. Current `worker-build`
        SigningWorker wasm is 1,428,715 bytes / gzip 499,797 bytes; total
        package is 1,461,905 bytes / gzip 507,425 bytes; Wrangler dry-run
        upload is 1445.60 KiB / gzip 497.99 KiB.
- [x] Benchmark setup/export latency with 1, 2, 3, and 4 A/B round trips.
  - [x] Add and run native Router adapter CPU benchmark:
        1 round trip 62.882 us; 2 round trips 82.568 us;
        3 round trips 102.72 us; 4 round trips 123.85 us.
- [x] Benchmark normal signing latency to confirm it remains close to the
      current single-SigningWorker path.
  - [x] Add and run native Router-to-SigningWorker hot-path benchmark:
        6.3362 us in a short Criterion sample. Scope: Router normal-signing
        admission metadata/check derivation, admission-store call construction,
        replay reservation call construction, active SigningWorker forwarding
        request construction, handler execution, and response binding
        validation. This excludes real Cloudflare network and storage latency.
- [x] Add Router A/B formal-verification parity targets to `just fv`.
  - [x] Run core source guards, evidence tests, protocol-boundary tests, Verus
        anti-drift tests, Verus proof checks, Lean boundary checks, and Lean
        privacy checks from `just router-ab-core-fv`.
  - [x] Align Verus and Lean role models with the current production roles:
        Router, Deriver A, Deriver B, and SigningWorker.
  - [x] Add initial Rust/FV anti-drift tests proving production role names and
        recipient-output authorization match the FV opened-value model.
- [x] Add activation-context anti-drift tests proving SigningWorker
      activation derives from public transcript state and rejects transcript
      digest or root-epoch drift.

### Phase 9B: Cloudflare Startup Latency Benchmark

Run this phase after the first real Cloudflare deployment or version upload of
the four-role Worker set. Dry-run upload is enough for bundle size, but it does
not emit `startup_time_ms`.

- [x] Add startup capture tooling:
      `pnpm -C crates/router-ab-cloudflare measure:startup-latencies` prints
      safe usage by default, `--dry-run` validates role upload shape without
      creating Worker versions, and `--upload` runs `wrangler versions upload`
      for Router, Deriver A, Deriver B, and SigningWorker while writing a JSON
      report with upload size and parsed `startup_time_ms`.
- [x] Deploy or `wrangler versions upload` Router, Deriver A, Deriver B, and
      SigningWorker with the same release artifacts measured in Phase 9.
- [x] Record Wrangler `startup_time_ms` for each role:
      Router, Deriver A, Deriver B, and SigningWorker.
- [x] Record the uploaded gzip size beside each `startup_time_ms` value so
      startup regressions can be compared against bundle growth.
- [x] Store startup upload evidence in the deployment evidence record. Keep the
      Phase 9B request-latency tasks below as follow-up runtime benchmarks.
- [ ] Exercise cold-ish normal signing path:
      `Client -> Router -> SigningWorker -> Router -> Client`.
  - [ ] Capture first-request latency after deploy/version upload.
  - [ ] Capture steady-state hot-isolate latency over repeated requests.
  - [ ] Confirm normal signing does not invoke Deriver A or Deriver B.
- [ ] Exercise cold-ish registration/export/refresh path:
      `Client -> Router -> Deriver A + Deriver B -> SigningWorker`.
  - [ ] Capture first-request latency after deploy/version upload.
  - [ ] Capture steady-state hot-isolate latency over repeated requests.
  - [ ] Confirm A/B coordination latency is separated from Worker startup.
- [ ] Pull Cloudflare metrics/logs for CPU time, wall time, invocation status,
      and startup failure events for each role.
- [ ] Compare results against the startup budget:
      excellent `< 100 ms`, acceptable `100-300 ms`, risky `300-700 ms`,
      unacceptable near `1000 ms`.
- [ ] If any role is risky, inspect the Wrangler startup CPU profile and remove
      top-level initialization, unused role code, or heavy dependencies from
      that role bundle.
- [ ] Add the measured startup table to the Bundle Size And Startup Budget
      section and keep it as a release-candidate gate.

### Phase 10: Production Rotation Revisit

This is production-hardening work, not a clean-MVP blocker. Revisit it after
the core Router/A/B architecture, admission path, deriver services, A/B
coordination, output delivery, and local validation are stable.
Do not pull this phase into the MVP implementation queue unless production
deployment requirements explicitly need key overlap before first launch.

- [ ] Add deriver-envelope HPKE key-epoch rotation semantics: current/previous
      epoch descriptors, request-TTL overlap, stale-epoch rejection, and
      current/previous epoch tests.
- [ ] Add deriver identity pinning and key-epoch rotation runbooks.
- [ ] Decide whether production rotations need sealed Durable Object or
      KMS-backed runtime unsealing beyond Cloudflare Secret binding rotation.

### Post-MVP Phase: ECDSA-HSS Router-A-B Version

Keep ECDSA-HSS outside the current Router A/B MVP. Add it after the
Ed25519-HSS/threshold-PRF provisioning flow is stable.

Security rationale:

- ECDSA-HSS already uses role-local additive derivation:
  `x = x_client + x_relayer mod n`.
- The existing `ecdsa-hss` specs require the production server boundary to
  avoid reconstructing canonical `x` and to avoid accepting both `y_client` and
  `y_relayer` in one process.
- A collapsed single-worker provisioning boundary that handles client secret
  bootstrap state plus relayer derivation/export state can reconstruct or log
  export-capable material. Router-A-B segregation reduces that risk by keeping
  root/provisioning material split across Deriver A and Deriver B.
- Normal ECDSA signing remains on the hot path:

  ```text
  Client -> Router -> SigningWorker -> Router -> Client
  ```

- Router-A-B applies to ECDSA registration, session bootstrap, recovery,
  explicit key export, and SigningWorker activation/refresh. It does not add
  A/B participation to each normal ECDSA signature.

Post-MVP todo:

- [ ] Define a distinct protocol version, for example
      `router_ab_ecdsa_hss_secp256k1_v1`.
- [ ] Map ECDSA-HSS role-local material into Deriver A/B outputs and
      SigningWorker activation records.
- [ ] Specify which ECDSA-HSS fields remain public transcript data, which are
      Deriver-local secret material, and which are SigningWorker-only material.
- [ ] Prove or test that no Router, Deriver, SigningWorker, log, audit event, or
      persistence record contains both sides needed to reconstruct canonical
      `x`, except the authorized client export runtime.
- [ ] Preserve the ECDSA-HSS export policy: explicit user confirmation,
      export-bound transcript, nonce replay protection, and client-side
      reconstruction/verification of `privateKeyHex`.
- [ ] Add secp256k1 public-key, Ethereum-address, low-s, recovery-id, and scalar
      validity vectors for the ECDSA-specific version.
- [ ] Benchmark ECDSA-HSS registration/export/activation latency separately
      from normal signing latency.
- [ ] Decide whether any future threshold/MPC ECDSA signing variant needs a
      separate online-signing protocol. Treat that as a different protocol from
      Router-A-B provisioning.

### Phase 11: Follow-Up Cleanup

These audit findings are real cleanup work, but they are not the lean Router A/B
MVP security boundary. Track them here so implementation does not drift away
from the MVP path.

- [x] Quarantine or delete public `split_root_derivation_v1` API exports.
      Retain split-root material only in specs, fixtures, or benches until its
      root-generation, anti-bias, refresh, leakage, and address-verification
      gates are accepted.
  - [x] Remove split-root candidate types and helpers from public
        `router-ab-core` derivation exports and delete the compiled
        implementation module.
  - [x] Delete the integration test suite that made the split-root prototype
        look like supported public API.
- [x] Delete the stale `evaluate_mpc_threshold_prf_candidate` placeholder.
  - [x] Quarantine the stale placeholder from public `router-ab-core`
        derivation exports. It remains private vector-gate scaffolding until
        the candidate-gate vectors are rewritten around the selected threshold
        backend path.
  - [x] Remove the private placeholder function and dead candidate-level
        input/output structs. Candidate output gate vectors now record the
        disabled `mpc_threshold_prf_v1` candidate-level path directly, while
        production continues to use proof-bundle backend APIs.
- [x] Collapse thin role-engine wrappers. Either make `DeriverAEngine`,
      `DeriverBEngine`, and `SigningWorkerEngine` own meaningful role-specific
      transitions, or remove them and keep the typed free functions as the
      public boundary.
  - [x] Delete pure host-holder `RouterEngine` and `RelayerEngine` wrappers.
  - [x] Keep the A/B deriver engine wrappers because they enforce
        role-specific threshold-PRF batch input before invoking the backend.
  - [x] Rename the public platform-agnostic A/B engine wrappers to
        `DeriverAEngine` and `DeriverBEngine`. The lower-level
        `Role::SignerA` / `Role::SignerB` wire labels remain a separate
        protocol-version decision.
- [x] Add boundary parser types for raw context, transcript, envelope header,
      and Minimum Level C evidence. After parsing, make core constructors and
      fields narrow enough that invalid internal shapes are hard to construct.
  - [x] Add `parse_context_v1`, `parse_transcript_v1`,
        `parse_envelope_header_v1`, and
        `parse_minimum_level_c_evidence_v1` with raw boundary structs.
  - [x] Add parser rejection tests for unsupported candidate labels,
        non-`all(2)` quorum policy, envelope kind/role mismatch, and malformed
        digest lengths.
  - [x] Ratchet core structs toward private fields or branch-specific builders
        so adapter code cannot bypass parser validation by direct struct
        literals.
    - [x] Make `EnvelopeHeaderV1` and `DeliveryPackageV1` constructor-only
          outside `derivation::envelope`, add accessors, and remove direct
          `Deserialize` from the typed envelope/package path.
    - [x] Remove direct `Deserialize` from typed state-machine branches and
          `MinimumLevelCVerificationInputV1` where they contain typed
          envelope/package values.
    - [x] Add source guards that prevent typed envelope/package and verifier
          input structs from regaining raw-boundary deserialization.
    - [x] Add validating `Deserialize` implementations for `RootShareEpoch`,
          `AccountScope`, `DerivationContext`, `IndexedSignerBinding`,
          `SignerSetBinding`, and `TranscriptBinding` so direct typed serde
          still runs constructor validation.
    - [x] Add typed serde rejection tests for empty context fields,
          non-`all(2)` signer-set quorum, and malformed transcript client key
          material.
    - [x] Add validating `Deserialize` implementations for
          `AuthenticatedSignerReceiptV1` and `MinimumLevelCEvidenceV1`, and
          keep `VerifiedMinimumLevelCEvidenceV1` out of direct typed serde.
    - [x] Make public Minimum Level C evidence types constructor/accessor-only,
          enforce exact two client and two SigningWorker/relayer package
          commitments, and add source guards against public-field regression.
    - [x] Tighten state-machine output binding so Minimum Level C ceremonies
          require exactly two client package commitments and exactly two
          SigningWorker/relayer package commitments.
    - [x] Add read-only accessors for account scope, context, signer entries,
          signer sets, and transcript bindings, then migrate the derivation
          layer and focused tests away from direct public field reads.
    - [x] Migrate the protocol payload conversion site that consumes a
          derivation `TranscriptBinding` to the new context accessor, with
          protocol-boundary and local-simulation tests passing.
    - [x] Make `AccountScope`, `DerivationContext`,
          `IndexedSignerBinding`, `SignerSetBinding`, and
          `TranscriptBinding` private-field, constructor/accessor-only types,
          and add source guards against public-field regression.
    - [x] Replace intentional invalid signer-set construction in parser,
          vectors, and tests with `SignerSetBinding::from_indexed_v1`, which
          rejects non-`all(2)` shapes at construction.
- [x] Decide whether protocol-local signer-set transport structs should also
      move to accessor-only APIs, or remain public internal wire shapes.
  - [x] Keep protocol-local signer-set, identity, lifecycle, and HTTP/local
        transport structs as public serde/wire shapes for now. They are
        validated at protocol boundaries and are separate from the derivation
        context/transcript invariant types.
- [x] Replace remaining heuristic joined-state string checks outside the MVP
      recipient-output path with typed boundaries and source guards.

## Open Decisions

- Do A and B live in separate Cloudflare accounts for production?
- Are same-account Service Bindings acceptable beyond prototype/local/dev?
- Which canonical byte encoding should selected production vectors freeze?
- Which values must be committed publicly so the client can detect bad output?
- What concrete performance budget would justify the stronger output
  correctness path?

## Non-Goals

- Full malicious-secure MPC proof system in the first implementation.
- Two-server online signing for every normal signature.
- Router-mediated plaintext A/B coordination.
- Compatibility with legacy joined-state server ceremonies beyond explicit
  persistence/request migration boundaries.

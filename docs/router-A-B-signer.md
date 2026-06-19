# Router A/B Deriver Architecture Plan

Date created: June 11, 2026

Status: design plan, prepared to start from Phase 0/Phase 1 after closing
refactor-66 as the retained registration baseline.

Spec:
[docs/router-A-B-signer-SPEC.md](./router-A-B-signer-SPEC.md).

Router A/B-only signing cleanup and release blockers:
[docs/router-a-b-cleanup.md](./router-a-b-cleanup.md).

Cloudflare Router A/B deployment is blocked until Ed25519 and ECDSA signing use
Router A/B as the only SDK/server signing architecture, and the old public
`/threshold-ed25519/*` and `/threshold-ecdsa/*` signing surfaces are removed or
explicitly moved out of release scope.

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
client never has joined d, a, y_server, tau_server
client opens only x_client_base
SigningWorker opens only x_server_base
```

The split values are algebraic relationships, not transport payloads:

```text
y_server = y_A + y_B
tau_server = tau_A + tau_B
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
- **Deriver quorum:** v1 is a strict 2-of-2 A/B ceremony. Generalized quorum
  work is tracked outside the release plan in
  [router-a-b-future-quorum.md](./router-a-b-future-quorum.md).
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
pnpm router:smoke:bundled
```

That profile exposes Router, Deriver A, Deriver B, and SigningWorker routes
from one process. It is local smoke and packaging coverage for route shape,
bindings, bundle construction, and parity checks. The strict release security
boundary is the four-role Cloudflare deployment.

Activation delivery should support a direct Deriver A/B -> SigningWorker fast
path because activation latency matters. Router still owns the public request,
admission, replay, lifecycle, selected SigningWorker identity, and final client
response. Derivers send only SigningWorker-recipient ciphertext/proof bundles to
the SigningWorker, and the SigningWorker returns an activation receipt to
Router. SigningWorker never coordinates A/B derivation.

Use `Deriver A`, `Deriver B`, and `SigningWorker` for new design prose and
APIs. Older `SignerA`/`SignerB` and `Server` labels in current code,
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

The client must never receive joined `d`, joined `a`, `y_server`, or
`tau_server`.

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
  requestKind: 'registration' | 'key_export' | 'recovery' | 'server_share_refresh';
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

| Product operation      | Primitive request kind | Reason                                                                          |
| ---------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| `registration_prepare` | `registration`         | creates the first account output relation after registration authorization      |
| `key_export`           | `export`               | re-opens existing account output material under export authorization            |
| `recovery`             | `export`               | re-opens existing account output material under recovery authorization          |
| `server_share_refresh` | `refresh`              | rotates future SigningWorker/root-share material and requires activation checks |

Recovery stays distinct in Router policy, auth, abuse controls, diagnostics,
and lifecycle state. It maps to primitive `export` because the derivation layer
does not create a new account relation for recovery; it releases existing
account-scoped output material after a different authority proof.

## Future Quorum Work

Router A/B v1 release work uses a strict 2-of-2 Deriver A plus Deriver B
ceremony. Generalized N-of-N and t-of-N quorum work is outside this release and
is tracked in [router-a-b-future-quorum.md](./router-a-b-future-quorum.md).

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
HSS work. This includes registration prepare, key export, recovery, server
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
A produces x_client_A and x_server_A
B produces x_client_B and x_server_B
```

Client-output material:

```text
A -> Client: EncryptToClient(x_client_A package)
B -> Client: EncryptToClient(x_client_B package)
Client opens x_client_base = x_client_A + x_client_B
```

SigningWorker-output material:

```text
A -> SigningWorker: x_server_A package
B -> SigningWorker: x_server_B package
SigningWorker opens x_server_base = x_server_A + x_server_B
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
Deriver A -> RecipientProofBundlePayloadV1(SigningWorker, x_server_base, deriver_a)
Deriver B -> RecipientProofBundlePayloadV1(SigningWorker, x_server_base, deriver_b)
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
   x_server_base locally.
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

The active SigningWorker holds `x_server_base`, which is allowed by the target
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
proof bundles, and the standalone SigningWorker receives only `x_server_base`
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

### Future Provider-Diverse Hardening

Provider-diverse and TEE-backed deriver deployments are future hardening work.
The current release path stays focused on the Cloudflare split-worker shape and
its deployed evidence gates. Future deployment choices, including multi-cloud
TEE placement and attestation-bound deriver identity, are tracked in
[router-a-b-deployment-choices.md](./router-a-b-deployment-choices.md).

### Promotion Criteria

Move from Stage 1 to Stage 2 after:

- Router opacity tests and source guards are passing.
- A/B role-boundary tests are passing.
- setup/export/refresh latency is acceptable.
- normal signing remains close to the single-SigningWorker path.
- key rotation and deriver identity pinning are implemented.

Move from separate Cloudflare accounts to provider-diverse hardening after:

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
- assert that the SigningWorker opens only `x_server_base`

This milestone should include negative tests for Router plaintext access,
wrong-role payloads, transcript mismatch, replay, expiry, and output-kind
confusion.

### Local Cryptographic Simulation

After the boundary simulation is stable, replace deterministic test-vector
outputs with the real derivation pieces:

- threshold-PRF partial evaluation or the selected split root derivation
- split `y_server` and `tau_server` material
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
- SigningWorker opens only `x_server_base` proof bundles
- Router never sees opened output material
- Deriver A/B never receive joined `y_server`, joined `tau_server`, joined
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
router:seed:sqlite
router:smoke
router:smoke:bundled
router:evidence
```

`router:seed:sqlite` should:

- create the local SQLite schema
- seed or verify signing-root metadata
- seed or verify role-specific sealed-share records
- print row counts and deriver roles from read-back verification
- verify Deriver A and Deriver B startup share availability through the local
  host-store boundary

`router:smoke` and `router:smoke:bundled` should:

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
must bind canonical inner bytes. For the current release, `WireMessageV1` is the
canonical inter-service wrapper: fixed field order, a
`router-ab-protocol/wire-message/v1` domain label, 32-bit big-endian length
prefixes, message-kind bytes, transcript digest bytes, and payload bytes. A
different codec requires a later protocol-version bump and fresh vectors.

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
- client-output proof bundles cannot be accepted as server output.
- server-output proof bundles cannot be accepted as client output.
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

Current evidence is tracked once in Phase 9B. The latest staging dry-run report
records role-specific upload sizes after ECDSA-HSS strict-route integration:
Router 2887.88 KiB / gzip 879.45 KiB, Deriver A 2336.55 KiB / gzip
737.40 KiB, Deriver B 2336.49 KiB / gzip 738.38 KiB, and SigningWorker
2784.06 KiB / gzip 896.44 KiB. Dry-run does not emit `startup_time_ms`, so real
startup evidence remains pending until Cloudflare upload or deploy.

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
- server-output proof bundle
- public transcript metadata

Production Router code must not import types that can decode deriver plaintext or
joined HSS state.

Production Deriver A code must not accept B-only plaintext types.

Production Deriver B code must not accept A-only plaintext types.

Production server code may accept only server-output proof bundles and the
opened `x_server_base`.

## Source Guards

Add source guards or type fixtures that fail when:

- Router production code imports HSS executor joined-state types.
- Router production code imports deriver plaintext envelope types.
- Deriver A routes accept B plaintext input.
- Deriver B routes accept A plaintext input.
- Any production route accepts `DdhHssSharedWord`, evaluator driver state, joined
  projector inputs, or raw joined client/server roots.
- Logs include protocol payload fields rather than hashes and public metadata.
- Client-output proof bundles can be sent to the server in plaintext.
- Server-output proof bundles can be sent to the client as server roots.

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

## Implementation Status

Detailed completed phase history, old status logs, and checklist snapshots were
archived to
[router-a-b-signer-implementation-history-2026-06-17.md](./audits/router-a-b-signer-implementation-history-2026-06-17.md).
Keep this file focused on the active Router A/B release architecture, durable
protocol decisions, and remaining evidence gates.

Current release state:

- `router-ab-core` owns the role-separated protocol types, lifecycle state,
  `WireMessageV1` canonical bytes, transcript binding, source guards, and local
  simulation.
- `router-ab-cloudflare` owns strict Router, Deriver A, Deriver B, and
  SigningWorker workers with role-specific bindings, private route boundaries,
  activation state, and release checks.
- SDK Ed25519 and ECDSA product signing use Router A/B Wallet Session V2 routes
  instead of the old public threshold signing surfaces.
- Remaining release evidence is deployed strict Cloudflare browser/runtime
  validation, including configured-origin success, rejected-origin behavior,
  preflight behavior, Worker startup/runtime metrics, and proof that old public
  threshold signing routes are absent.

## Open Decisions

- Do A and B live in separate Cloudflare accounts for production?
- Are same-account Service Bindings acceptable beyond prototype/local/dev?
- Which values must be committed publicly so the client can detect bad output?
- What concrete performance budget would justify the stronger output
  correctness path?

## Non-Goals

- Full malicious-secure MPC proof system in the first implementation.
- Two-server online signing for every normal signature.
- Router-mediated plaintext A/B coordination.
- Compatibility with legacy joined-state server ceremonies beyond explicit
  persistence/request migration boundaries.

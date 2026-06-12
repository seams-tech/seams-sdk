# Router A/B Signer Architecture Plan

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
Relayer-output shares go only to the designated relayer.
```

The target is to remove joined sensitive derivation state from any single
server-side production process during registration, key export, recovery, and
relayer-share refresh.

Normal day-to-day signing should remain a client plus one relayer flow after the
split setup path has produced the relayer's allowed output share.

## Security Target

This architecture targets the Level C invariant from the malicious-security
plan:

```text
server never has joined d, a, x_client_base
client never has joined d, a, y_relayer, tau_relayer
client opens only x_client_base
server opens only x_relayer_base
```

The split values are algebraic relationships, not transport payloads:

```text
y_relayer = y_A + y_B
tau_relayer = tau_A + tau_B
y_client = y_client_A + y_client_B
tau_client = tau_client_A + tau_client_B
```

No router, signer, coordinator, persistence layer, log sink, or diagnostics
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
- **Relayer placement:** Signer A is the initial designated relayer.
- **Signer quorum:** v1 is a strict 2-of-2 A/B ceremony. Protocol and lifecycle
  types should still model an indexed signer set internally so future N-of-N or
  t-of-N work can reuse the architecture after protocol review.
- **Lifecycle:** use one `DerivationCeremony` state machine with
  request-kind-specific scope.
- **Signer identity and rotation:** bind protocol version, request kind,
  account/session, signing root version, root-share epoch, signer A/B identity
  and key epochs, relayer identity and key epoch, client ephemeral key, Router
  request digest, nonce, and expiry into the transcript.
- **Observability:** use typed redacted diagnostics plus source guards.
- **Local/prod parity:** keep strict role, key, process, and wire-protocol
  separation from local simulation onward.
- **Rust/Wasm bundle discipline:** build separate role bundles and measure size,
  startup, and CPU for every release candidate.
- **Recovery/migration:** address verification is a release gate before
  production root rotation.

## Topology

```text
                         direct authenticated A/B channel
                    +---------------------------------------+
                    |                                       |
                    v                                       v
+--------+     +----------+       +----------+        +----------+
| Client | --> |  Router  | ----> | Signer A |        | Signer B |
+--------+     +----------+       +----------+        +----------+
    ^               |                  |                   |
    |               |                  +-------------------+
    |               |                         A/B MPC
    |               |
    +---------------+
       encrypted client packages
```

The Router is the only public API surface used by clients. It authenticates the
user/session, applies rate limits, checks request shape, and forwards opaque
role-specific envelopes to A and B.

A and B decrypt only their own envelopes, then coordinate directly over
mutually authenticated internal endpoints. The Router does not broker A/B
protocol messages in the primary design.

## Roles

### Client

- Derives client-side material.
- Splits client material into A-side and B-side shares.
- Encrypts role-specific envelopes for A and B.
- Sends one request to the Router.
- Receives encrypted output packages from A and B through the Router.
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

The Router must treat signer payloads as opaque ciphertext. It must never
decrypt signer envelopes, inspect HSS state, combine A/B shares, or persist
protocol payload plaintext.

### Signer A

- Holds A-side relayer root material such as `y_A` and `tau_A`.
- Receives only A-side client shares.
- Runs the A role in the direct A/B protocol.
- Emits A-side client-output material encrypted to the client.
- Emits A-side relayer-output material to the designated relayer.

Signer A must never receive B's raw shares or enough B-side state to reconstruct
joined `d`, `a`, or `x_client_base`.

### Signer B

- Holds B-side relayer root material such as `y_B` and `tau_B`.
- Receives only B-side client shares.
- Runs the B role in the direct A/B protocol.
- Emits B-side client-output material encrypted to the client.
- Emits B-side relayer-output material to the designated relayer.

Signer B must never receive A's raw shares or enough A-side state to reconstruct
joined `d`, `a`, or `x_client_base`.

### Designated Relayer

- Receives relayer-output shares only.
- Opens `x_relayer_base`.
- Handles normal signing with the client after setup/export/refresh completes.

The initial designated relayer is Signer A. B may send relayer-output material
to A, but B must encrypt B-side client-output material directly to the client.
Router must remain secret-light and must not activate or store
`x_relayer_base`.

Later deployments may move the relayer into a separate service if operational
separation justifies the added deployment surface.

## Request Shape

The client sends one Router request containing public routing metadata and two
role-specific encrypted envelopes:

```ts
type RouterSplitSignerRequest = {
  protocolVersion: string;
  requestKind:
    | 'registration'
    | 'key_export'
    | 'recovery'
    | 'relayer_share_refresh';
  accountId: string;
  sessionId: string;
  transcriptNonce: string;
  expiresAtMs: number;
  clientEphemeralPublicKey: string;
  aEnvelope: EncryptedSignerEnvelope;
  bEnvelope: EncryptedSignerEnvelope;
};
```

Each encrypted signer envelope must bind:

- `protocolVersion`
- `requestKind`
- `accountId`
- `sessionId`
- `transcriptNonce`
- `expiresAtMs`
- signer role, `A` or `B`
- client ephemeral public key
- Router request digest

The plaintext inside `aEnvelope` is valid only for A. The plaintext inside
`bEnvelope` is valid only for B.

### Product-To-Primitive Request Mapping

Router-facing product operations remain more specific than primitive derivation
request kinds:

| Product operation | Primitive request kind | Reason |
| --- | --- | --- |
| `registration_prepare` | `registration` | creates the first account output relation after registration authorization |
| `key_export` | `export` | re-opens existing account output material under export authorization |
| `recovery` | `export` | re-opens existing account output material under recovery authorization |
| `relayer_share_refresh` | `refresh` | rotates future relayer/root-share material and requires activation checks |

Recovery stays distinct in Router policy, auth, abuse controls, diagnostics,
and lifecycle state. It maps to primitive `export` because the derivation layer
does not create a new account relation for recovery; it releases existing
account-scoped output material after a different authority proof.

## Future N-Of-N And T-Of-N Generalization

Router A/B should ship first as a 2-of-2 system: Signer A and Signer B must both
participate in each derivation-time ceremony. Generalizing beyond two signers is
useful future work, especially for operator diversity, maintenance windows, and
stronger availability, but it must not expand the first release's security
claim.

There are two future shapes:

- **N-of-N:** every configured signer participates. This is the direct extension
  of A/B and mainly changes request framing, transcript binding, signer-set
  management, and operational liveness. One unavailable signer blocks the
  ceremony.
- **t-of-N:** any approved quorum can participate, such as 2-of-3 or 3-of-5.
  This is a larger protocol change. It requires threshold share indexing,
  quorum selection, transcript binding to the selected signer set, replay and
  equivocation handling, commitments or verifying-share checks, and reviewed
  refresh/reshare semantics.

To keep the upgrade path open, v1 implementation should avoid hard-coding A/B
as a transport shape below the product API boundary. The protocol crate should
prefer signer-set concepts even while enforcing `quorumPolicy = all(2)`:

```ts
type SplitSignerSet = {
  signerSetId: string;
  threshold: 2;
  signers: readonly [
    { role: 'A'; signerId: string; keyEpoch: string },
    { role: 'B'; signerId: string; keyEpoch: string },
  ];
};

type RouterSplitSignerRequestV1 = {
  protocolVersion: string;
  requestKind:
    | 'registration'
    | 'key_export'
    | 'recovery'
    | 'relayer_share_refresh';
  signerSet: SplitSignerSet;
  signerEnvelopes: readonly [
    RoleEncryptedEnvelope<'A'>,
    RoleEncryptedEnvelope<'B'>,
  ];
};
```

The public examples may continue to name `aEnvelope` and `bEnvelope` for
readability, but canonical transcript bytes should bind signer-set id, signer
index, role, key epoch, quorum policy, selected relayer identity, and the
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
  -> forward A envelope to Signer A
  -> forward B envelope to Signer B
  -> wait for encrypted signer responses
  -> verify public response metadata and transcript digest agreement
  -> return encrypted A/B client packages to the client
```

The Router should persist only public lifecycle state:

- request id
- account id
- session id
- request kind
- protocol version
- transcript nonce hash
- encrypted-envelope digest set
- signer response hashes
- public transcript digest
- lifecycle status
- timing and error codes

It must not persist decrypted signer envelopes, A/B protocol payloads, output
shares, HSS driver state, OT state, or joined words.

## Expensive-Work Admission Gate

The Router owns admission for any request that can trigger expensive signer or
HSS work. This includes registration prepare, key export, recovery, relayer
share refresh, and any future precompute route. The gate runs after cheap
request normalization and policy checks, and before the Router forwards work to
Signer A or Signer B.

The gate protects two resources:

- public Router CPU and queue slots
- private signer CPU, queues, and A/B protocol capacity

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
      reason: 'short_window_saturated' | 'signer_queue_saturated';
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
- saturated signer queues should return `defer` so the caller can run the
  slower post-auth path or retry later
- rejected requests must stop before Signer A, Signer B, or HSS prepare work
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

A -> Router: encrypted client package A, relayer package A status
B -> Router: encrypted client package B, relayer package B status
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

Relayer-output material:

```text
A -> Relayer: x_relayer_A package
B -> Relayer: x_relayer_B package
Relayer opens x_relayer_base = x_relayer_A + x_relayer_B
```

If the Router aggregates responses, it aggregates ciphertext only:

```ts
type RouterSplitSignerResponse = {
  requestId: string;
  protocolVersion: string;
  requestKind: RouterSplitSignerRequest['requestKind'];
  accountId: string;
  sessionId: string;
  transcriptNonce: string;
  publicTranscriptDigest: string;
  aClientPackage: EncryptedClientPackage;
  bClientPackage: EncryptedClientPackage;
};
```

The Router may verify public transcript hashes and signer signatures, but it
must not be able to decrypt `aClientPackage` or `bClientPackage`.

Strict production delivery uses `RecipientProofBundlePayloadV1` rather than a
joined output package. Each signer filters its proof batch into a single
recipient-scoped payload before delivery:

```text
Signer A -> RecipientProofBundlePayloadV1(client, x_client_base, signer_a)
Signer B -> RecipientProofBundlePayloadV1(client, x_client_base, signer_b)
Signer A -> RecipientProofBundlePayloadV1(relayer, x_relayer_base, signer_a)
Signer B -> RecipientProofBundlePayloadV1(relayer, x_relayer_base, signer_b)
```

The canonical payload binds lifecycle id, producing signer identity, recipient
role, opened-share kind, recipient identity, transcript digest, and the nested
single-bundle proof batch. The decoder rejects payloads that contain more than
one proof bundle, target the wrong recipient class, or mismatch the enclosed
proof-batch binding. The wire kind is `recipient_proof_bundle`.

`RecipientProofBundleCiphertextV1` encrypts that canonical payload to the final
recipient and is the payload carried by the public
`recipient_proof_bundle` wire kind. Its public header and AAD bind algorithm,
producing signer identity, recipient role, opened-share kind, recipient
identity, recipient encryption key, transcript digest, payload digest, and
nonce. Cloudflare uses HPKE base mode with X25519, HKDF-SHA256, and AES-256-GCM
for this envelope.

The first deployable strict profile should be:

```text
1. A and B decrypt only their own role envelopes.
2. A and B run the authenticated A/B proof-batch exchange.
3. A and B filter full proof batches into client and relayer
   RecipientProofBundlePayloadV1 values.
4. A and B encrypt each recipient payload to the final recipient key.
5. Router forwards opaque encrypted client bundles in the public response.
6. Signer A relayer receives only opaque encrypted relayer bundles and opens
   x_relayer_base locally.
7. Client opens only x_client_base locally.
```

## Normal Signing Flow

The split A/B path is used for derivation-time operations:

- registration
- recovery
- key export
- relayer-share refresh

Day-to-day signing should use the existing product shape:

```text
Client -> Router -> designated relayer
```

The designated relayer holds `x_relayer_base`, which is allowed by the target
security model. Normal signing should not require Signer A and Signer B to both
be online unless the product intentionally selects full two-server online
signing.

## Failure Model

The Router can:

- deny service
- drop or delay messages
- send stale envelopes
- route to the wrong signer
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

Every signer must verify that its decrypted envelope and A/B protocol messages
bind to the same transcript:

- `protocolVersion`
- `requestKind`
- `accountId`
- `sessionId`
- `requestId`
- `transcriptNonce`
- `expiresAtMs`
- client ephemeral public key
- signer role
- peer signer identity
- designated relayer identity
- Router request digest
- public account verifying key or intended account id binding

Signer responses must include a signer signature over the final public
transcript digest.

The client must verify:

- A and B packages bind to the same transcript.
- A package came from A.
- B package came from B.
- The packages target the client's ephemeral public key.
- The output kind is client output.
- The request kind and account/session bindings match the original request.

The relayer must verify:

- relayer-output packages bind to the same transcript.
- packages came from the expected A and B identities.
- the output kind is relayer output.
- account and signing-root bindings match the relayer session.

## Cloudflare Deployment Shape

Recommended initial deployment:

```text
Router Worker: public endpoint, auth, policy, rate limits
Signer A Worker: private/internal endpoint and initial relayer
Signer B Worker: private/internal endpoint
```

A separate Relayer Worker is a later hardening option. The first deployment
keeps normal signing on `Client -> Router -> Signer A`.

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
  allowed signer-envelope AEAD keys:
    none
  allowed A/B peer signing keys:
    none
  allowed A/B peer verifying keys:
    optional public config only
  forbidden Durable Object scopes:
    Signer A sealed root shares
    Signer B sealed root shares
    relayer-output activation state
  forbidden signer-envelope AEAD keys:
    Signer A signer-envelope key
    Signer B signer-envelope key
  forbidden A/B peer signing keys:
    Signer A peer-message signing key
    Signer B peer-message signing key

Signer A Worker + relayer role:
  allowed Durable Object scopes:
    Signer A sealed root shares
    Signer A relayer-output activation state
  allowed signer-envelope AEAD keys:
    Signer A signer-envelope key
  allowed A/B peer signing keys:
    Signer A peer-message signing key
  allowed A/B peer verifying keys:
    Signer A and Signer B peer-message verifying keys
  forbidden Durable Object scopes:
    Signer B sealed root shares
    Router replay state
  forbidden signer-envelope AEAD keys:
    Signer B signer-envelope key
  forbidden A/B peer signing keys:
    Signer B peer-message signing key

Signer B Worker:
  allowed Durable Object scopes:
    Signer B sealed root shares
  allowed signer-envelope AEAD keys:
    Signer B signer-envelope key
  allowed A/B peer signing keys:
    Signer B peer-message signing key
  allowed A/B peer verifying keys:
    Signer A and Signer B peer-message verifying keys
  forbidden Durable Object scopes:
    Signer A sealed root shares
    relayer-output activation state
    Router replay state
  forbidden signer-envelope AEAD keys:
    Signer A signer-envelope key
  forbidden A/B peer signing keys:
    Signer A peer-message signing key
```

For the first same-account prototype, these can be separate bindings in one
Cloudflare account:

```text
ROUTER_REPLAY_DO
ROUTER_LIFECYCLE_DO
SIGNER_A_ROOT_SHARE_DO
SIGNER_A_RELAYER_OUTPUT_DO
SIGNER_B_ROOT_SHARE_DO
SIGNER_A_ENVELOPE_AEAD_KEY
SIGNER_B_ENVELOPE_AEAD_KEY
SIGNER_A_PEER_SIGNING_KEY
SIGNER_B_PEER_SIGNING_KEY
SIGNER_A_PEER_VERIFYING_KEY_HEX
SIGNER_B_PEER_VERIFYING_KEY_HEX
```

For the stronger multi-account deployment, each account should own only the
bindings it needs:

```text
Router account:
  ROUTER_REPLAY_DO
  ROUTER_LIFECYCLE_DO

Signer A account:
  SIGNER_A_ROOT_SHARE_DO
  SIGNER_A_RELAYER_OUTPUT_DO
  SIGNER_A_ENVELOPE_AEAD_KEY
  SIGNER_A_PEER_SIGNING_KEY
  SIGNER_A_PEER_VERIFYING_KEY_HEX
  SIGNER_B_PEER_VERIFYING_KEY_HEX

Signer B account:
  SIGNER_B_ROOT_SHARE_DO
  SIGNER_B_ENVELOPE_AEAD_KEY
  SIGNER_B_PEER_SIGNING_KEY
  SIGNER_A_PEER_VERIFYING_KEY_HEX
  SIGNER_B_PEER_VERIFYING_KEY_HEX
```

Signer-envelope decrypt keys and A/B peer-message signing keys are Cloudflare
Secret bindings. A/B peer-message verifying keys are public lowercase-hex
Ed25519 keys. The typed startup parser receives only public descriptors and
public verifying-key bytes:

```text
SIGNER_A_ENVELOPE_AEAD_KEY_BINDING=SIGNER_A_ENVELOPE_AEAD_KEY
SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH=envelope-key-epoch-a
SIGNER_B_ENVELOPE_AEAD_KEY_BINDING=SIGNER_B_ENVELOPE_AEAD_KEY
SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH=envelope-key-epoch-b
SIGNER_A_PEER_SIGNING_KEY_BINDING=SIGNER_A_PEER_SIGNING_KEY
SIGNER_A_PEER_SIGNING_KEY_EPOCH=key-epoch-a
SIGNER_B_PEER_SIGNING_KEY_BINDING=SIGNER_B_PEER_SIGNING_KEY
SIGNER_B_PEER_SIGNING_KEY_EPOCH=key-epoch-b
SIGNER_A_PEER_VERIFYING_KEY_HEX=<64 lowercase hex chars>
SIGNER_B_PEER_VERIFYING_KEY_HEX=<64 lowercase hex chars>
```

`workers-rs` startup validation checks the configured Secret binding exists,
without loading the key into startup diagnostics. Signer A startup rejects any
Signer B envelope-key or peer-signing-key descriptor. Signer B startup rejects
any Signer A envelope-key or peer-signing-key descriptor. Router startup rejects
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

relayer_output.activate {
  transcriptDigest,
  relayerIdentity,
  rootShareEpoch,
  packageDigest
}

router_replay.reserve {
  requestId,
  transcriptDigest,
  expiresAtMs
}
```

Signer startup must fail closed if the role-specific root-share Durable Object
binding is missing, points at the wrong storage scope, lacks the expected
signer-set id, lacks the expected root-share epoch, or returns a signer role
that differs from the Worker role. Router startup must fail if it receives any
signer root-share or relayer-output binding.

The first `router-ab-cloudflare` crate should pin this boundary with typed
binding descriptors, role-specific startup configs, and validation tests before
adding `workers-rs` request handlers. The later `workers-rs` layer should be a
thin adapter from `worker::Env` and Service Bindings into those typed configs
and the existing `router-ab-core` host traits.

## Production A/B Orchestration Decision

Strict server-blind production uses recipient-side combine. A and B return only
recipient-scoped proof-batch material: the client receives only `x_client_base`
proof bundles, and the designated relayer receives only `x_relayer_base` proof
bundles. Each recipient combines its own output locally. Router may relay opaque
bundles, but it must not decrypt them or combine recipient outputs.

The decrypted delivery unit is `RecipientProofBundlePayloadV1`, and the public
wire payload for `WireMessageKindV1::RecipientProofBundle` is
`RecipientProofBundleCiphertextV1`. The decrypted payload is a signer-produced,
recipient-scoped proof-batch wrapper. It must contain exactly one proof bundle
whose binding matches the declared recipient role, opened-share kind,
recipient identity, transcript digest, and producing signer identity. Router
adapters may route or store the encrypted envelope bytes; combine authority
stays with the final recipient.

Alternative shapes remain documented for deployment profiles with weaker or
different tradeoffs:

- **Encrypted rendezvous:** A and B post peer bundles into a transcript-scoped
  rendezvous, such as a Durable Object, while encrypting each bundle to the
  final recipient. This preserves Router opacity and gives Cloudflare-native
  coordination. It adds timeout, replay, cleanup, and
  equivocation handling.
- **Signer-side combine:** A and B exchange proof batches and a signer produces
  final output packages. This is the simplest route shape and matches the
  current preloaded test handler. It weakens the strict server-blind invariant
  unless the combiner runs inside a separately trusted boundary.

Implementation note for v1 strict delivery: an A-to-B or B-to-A peer message is
not enough for the recipient signer to produce its own proof batch. The
recipient signer also needs its own Router-to-signer encrypted envelope,
role-envelope AAD, request-context digest, root-share metadata, and root-share
wire. Router therefore dispatches independently to A and B, and the strict
Router response path requires both signer responses before returning client
bundles or activating relayer bundles. Transcript-scoped rendezvous remains
future hardening work.

Release gate:

- The strict production route must expose recipient-scoped proof-batch delivery,
  not signer-side output packaging.
- The public wire payload must be `RecipientProofBundleCiphertextV1` or a later
  encrypted version, and the decrypted payload must preserve the same
  one-recipient invariant.
- The client path must reject any relayer-output proof bundle.
- The relayer path must reject any client-output proof bundle.
- Any signer-side combine path must be labeled as a weaker deployment profile
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
  Signer A Worker + relayer role
  Signer B Worker
  same-account Service Bindings
```

This stage optimizes for development speed, low latency, and operational
simplicity. It should validate:

- role-specific encrypted envelopes
- Router opacity
- A-only and B-only plaintext boundaries
- direct A/B protocol behavior
- client-output encryption
- relayer-output activation in Signer A
- setup/export/refresh latency
- normal signing latency through Router plus Signer A

Even in this stage, the Router must see only ciphertext and public metadata.
Signer A and Signer B must use the same role-specific APIs that a future
multi-account or multi-cloud deployment would use.

### Stage 2: Separate Cloudflare Accounts

```text
Cloudflare account 1:
  Router Worker

Cloudflare account 2:
  Signer A Worker + relayer role

Cloudflare account 3:
  Signer B Worker

optional Cloudflare account 4:
  Relayer Worker
```

This stage increases operational separation while keeping the same provider and
deployment model. A separate relayer account is optional later. This stage adds:

- separate Cloudflare account credentials
- separate deploy tokens
- separate secrets and signer keys
- separate logs and alerting
- authenticated HTTPS between Router, A, and B
- stronger blast-radius reduction for control-plane compromise

The protocol should not change at this stage. The transport changes from
same-account Service Bindings to authenticated cross-account HTTPS, and the
signer identity registry should pin the expected public keys for A, B, Router,
and the relayer role hosted by A.

### Stage 3: Multi-Cloud TEE Signers

```text
Cloudflare:
  Router Worker

AWS:
  Signer A + relayer role on Nitro Enclave-backed service

Google Cloud:
  Signer B on Confidential VM/service

optional hardened service:
  separate Relayer
```

This stage adds provider diversity and hardware-backed execution boundaries for
the split signer roles. It should bind signer identity to attestation evidence:

```text
signer role
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
- A single signer TEE compromise exposes only that signer's split role.
- The protocol still prevents any one signer from opening joined `d`, `a`, or
  `x_client_base`.

### Promotion Criteria

Move from Stage 1 to Stage 2 after:

- Router opacity tests and source guards are passing.
- A/B role-boundary tests are passing.
- setup/export/refresh latency is acceptable.
- normal signing remains close to the single-relayer path.
- key rotation and signer identity pinning are implemented.

Move from Stage 2 to Stage 3 after:

- signer identity is already transcript-bound.
- attestation evidence can be verified and pinned.
- deployment epochs and rollback policy are defined.
- incident response can rotate either signer independently.
- the added latency and operational complexity are justified by customer or
  threat-model requirements.

## Local Development Simulation

Local development should simulate the split trust domains before any Cloudflare
deployment. The first useful shape is three local services plus local durable
state:

```text
localhost:8787  Router
localhost:8788  Signer A + relayer role
localhost:8789  Signer B
local Postgres  signing-root metadata and sealed-share records
```

Each service should run as its own process with its own environment file and
role-specific secrets:

```text
router.env:
  ROUTER_SIGNING_KEY
  SIGNER_A_URL
  SIGNER_B_URL
  no share decrypt keys
  no signer-envelope AEAD keys

signer-a.env:
  SIGNER_ROLE=A
  SIGNER_A_ENVELOPE_AEAD_KEY
  SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH
  SIGNER_A_PEER_SIGNING_KEY
  SIGNER_A_PEER_SIGNING_KEY_EPOCH
  SIGNING_ROOT_SHARE_A_KEK
  RELAYER_OUTPUT_STORAGE
  SIGNER_B_URL

signer-b.env:
  SIGNER_ROLE=B
  SIGNER_B_ENVELOPE_AEAD_KEY
  SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH
  SIGNER_B_PEER_SIGNING_KEY
  SIGNER_B_PEER_SIGNING_KEY_EPOCH
  SIGNING_ROOT_SHARE_B_KEK
  SIGNER_A_URL
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
- run Router, Signer A/Relayer, and Signer B as separate processes
- generate deterministic dev output shares from transcript-bound test vectors
- send one client request to the Router containing encrypted A and B envelopes
- have Router forward opaque envelopes without decrypting them
- have A and B decrypt only their own envelopes
- have A and B coordinate directly over local HTTP
- return encrypted client-output packages through the Router
- deliver relayer-output packages only to Signer A's local relayer role
- assert that the client opens only `x_client_base`
- assert that the relayer opens only `x_relayer_base`

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
- relayer-output delivery to the designated relayer
- address and public-key parity tests before and after root-share refresh

The local cryptographic simulation must preserve the same invariant as
production:

```text
Router never decrypts signer envelopes.
A never receives B plaintext.
B never receives A plaintext.
No local service materializes joined d, a, or x_client_base.
Normal signing uses Router plus one relayer.
```

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
- print row counts and signer roles from read-back verification
- verify Signer A and Signer B startup share availability through the local
  host-store boundary

`dev:router-ab-signer` should:

- allocate service ports
- write or load service-specific dev env files
- start Router, Signer A/Relayer, and Signer B
- print the Router URL as the only client-facing endpoint

The script should fail closed if Router has any share decrypt key, if Signer A
has B-only keys, if Signer B has A-only keys, or if required transcript-binding
configuration is missing.

## Rust/Wasm Implementation Architecture

The implementation should put the protocol-critical code and A/B signer logic
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
  client-output and relayer-output package validation

platform-agnostic signer engines:
  Signer A engine
  Signer B engine
  relayer activation engine
  host traits for clock, randomness, storage, keys, transport, and audit

workers-rs wrappers:
  Router Worker HTTP entrypoint
  Signer A Worker HTTP entrypoint and relayer activation endpoint
  Signer B Worker HTTP entrypoint
  optional separate Relayer Worker HTTP entrypoint
  Cloudflare Env bindings
  fetch/service-binding transport adapters
  response mapping

TypeScript:
  optional build/test harness glue
  optional host implementation using the same canonical wire protocol
  optional Wasm/npm consumer of the Rust protocol core
```

Router, Signer A/Relayer, and Signer B may all be Rust Workers. The protocol
boundary should still use portable request/response envelopes rather than
Cloudflare-specific object RPC:

```text
Router -> Signer A: request carrying encrypted A envelope
Router -> Signer B: request carrying encrypted B envelope
A <-> B: request carrying transcript-bound protocol messages
Router -> Signer A relayer role: request carrying relayer-output package
```

That keeps the same core usable across:

- local localhost simulation
- same-account Cloudflare Service Bindings
- cross-account Cloudflare HTTPS
- future AWS Nitro or Google Cloud Confidential signer services

### Platform-Agnostic Signer Engines

Signer A and Signer B should be ordinary Rust engines that know nothing about
Cloudflare, HTTP frameworks, environment variables, service bindings, or
TypeScript runtimes.

The core shape should be:

```rust
pub struct SignerEngine<R, H> {
    role: R,
    host: H,
}

impl<R, H> SignerEngine<R, H>
where
    R: SignerRole,
    H: SignerHost,
{
    pub async fn handle_envelope(
        &self,
        input: SignerEnvelopeRequest,
    ) -> Result<SignerEnvelopeResponse, SignerError> {
        // role-specific protocol logic
    }
}
```

The host boundary should be a small set of traits:

```rust
pub trait SignerHost:
    Clock
    + Csprng
    + SignerKeyStore
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
pub struct CloudflareSignerHost {
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
Router -> A: SignerARequestBytes
Router -> B: SignerBRequestBytes
A <-> B: AbProtocolMessageBytes
A/B -> Router: SignerResponseBytes
Router -> Relayer: RelayerActivationBytes
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
- parse `worker::Env` into a `CloudflareSignerHost`
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
      candidate_split_root.rs
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
        signer_a.rs
        signer_b.rs
        relayer.rs
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

- Router cannot construct signer plaintext.
- A-only input cannot enter B-only state.
- B-only input cannot enter A-only state.
- client-output packages cannot be accepted as relayer output.
- relayer-output packages cannot be accepted as client output.
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
- keep Router, Signer A/Relayer, and Signer B as separate Workers so each
  bundle carries only its deployment role's code
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

Current local release artifacts, captured June 12, 2026:

```text
command:
  cargo build --manifest-path crates/router-ab-cloudflare/Cargo.toml \
    --target wasm32-unknown-unknown \
    --features <entrypoint-feature> \
    --release

artifact:
  crates/router-ab-cloudflare/target/wasm32-unknown-unknown/release/router_ab_cloudflare.wasm

profile:
  role-specific strict Worker entrypoint features
  no wasm-opt pass
  no Wrangler bundling pass

sizes:
  strict-worker-entrypoint          combined role dispatch  2,370,450 bytes  gzip 671,138 bytes
  strict-worker-router-entrypoint   Router                  1,836,346 bytes  gzip 487,682 bytes
  strict-worker-signer-a-entrypoint Signer A/Relayer        2,126,483 bytes  gzip 614,303 bytes
  strict-worker-signer-b-entrypoint Signer B                1,990,085 bytes  gzip 577,469 bytes
```

Current optimized `worker-build` and Wrangler dry-run artifacts, captured
June 12, 2026:

```text
commands:
  pnpm -C crates/router-ab-cloudflare measure:strict-workers
  pnpm -C crates/router-ab-cloudflare dry-run:router
  pnpm -C crates/router-ab-cloudflare dry-run:signer-a
  pnpm -C crates/router-ab-cloudflare dry-run:signer-b

profile:
  worker-build 0.8.4 release
  wasm-opt@130 through worker-build
  wrangler 4.40.3 deploy --dry-run
  deployment-shaped per-role Wrangler configs with Durable Object and Service
  Binding entries

optimized worker-build wasm:
  strict-worker-entrypoint          combined role dispatch  1,505,206 bytes  gzip 561,307 bytes
  strict-worker-router-entrypoint   Router                  1,066,608 bytes  gzip 380,786 bytes
  strict-worker-signer-a-entrypoint Signer A/Relayer        1,321,089 bytes  gzip 498,834 bytes
  strict-worker-signer-b-entrypoint Signer B                1,252,900 bytes  gzip 479,720 bytes

wrangler dry-run Total Upload:
  Router           1088.52 KiB  gzip 381.52 KiB
  Signer A/Relayer 1340.19 KiB  gzip 497.55 KiB
  Signer B         1273.60 KiB  gzip 478.68 KiB
```

These are below Cloudflare's gzip size limit. The remaining release gate is
Wrangler or deployed `startup_time_ms` evidence with real deployment values.
The current Wrangler files include DO classes, migrations, and Service
Bindings; production still needs real verifying-key values, Cloudflare secrets
under the configured secret binding names, and route/account selection.

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
+ one relayer call
+ signing compute
```

Normal signing should stay close to the current single-relayer behavior.

## Type And Boundary Requirements

Make invalid states unrepresentable at the TypeScript and Rust boundaries.

Route/domain types should distinguish:

- public Router request metadata
- opaque encrypted A envelope
- opaque encrypted B envelope
- decrypted A-only signer input
- decrypted B-only signer input
- A/B protocol messages
- encrypted client-output package
- relayer-output package
- public transcript metadata

Production Router code must not import types that can decode signer plaintext or
joined HSS state.

Production Signer A code must not accept B-only plaintext types.

Production Signer B code must not accept A-only plaintext types.

Production relayer code may accept only relayer-output packages and the opened
`x_relayer_base`.

## Source Guards

Add source guards or type fixtures that fail when:

- Router production code imports HSS executor joined-state types.
- Router production code imports signer plaintext envelope types.
- Signer A routes accept B plaintext input.
- Signer B routes accept A plaintext input.
- Any production route accepts `DdhHssSharedWord`, evaluator driver state, joined
  projector inputs, or raw joined client/server roots.
- Logs include protocol payload fields rather than hashes and public metadata.
- Client-output packages can be sent to the relayer in plaintext.
- Relayer-output packages can be sent to the client as relayer roots.

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

- Expensive-work admission must happen before signer/HSS work and derive its
  context from trusted Router metadata, never client JSON.
- Early prepare/precompute must use an explicit scoped handle that binds auth
  method, wallet/account, rp id, signer mode, intent digest, and protocol
  context.
- Prepared work must be short-lived, replay-protected, and single-use.
- Under load, the Router can defer early prepare and fall back to the slower
  authority-verified path.
- Diagnostics stay observational and must cover browser-visible total, SDK
  visible total, post-auth visible total, hidden prepare work, signer queue wait,
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
4. Add Cloudflare Router, Signer A/Relayer, and Signer B adapters after the
   local boundary tests prove role separation, replay handling, and output-kind
   separation.

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
  signer-envelope wrappers, canonical wire-message wrappers, platform-agnostic
  engine wrappers, host traits, and source guards against platform imports.
- Initial wire-message canonical encoding and digest helpers are implemented
  with versioned, length-prefixed field order.
- Cross-host wire-vector fixtures are committed for Router-to-A, Router-to-B,
  A-to-B, B-to-A, signer response, and relayer activation messages.
- Role-specific client-output and relayer-output package types are implemented
  with fixed recipient/opened-share semantics.
- Signer identity, signer key epoch, selected relayer identity, v1 all(2)
  signer-set, and role-envelope assignment types are implemented.
- Exact service payload structs are implemented for Router-to-signer, A/B peer
  messages, signer responses, and relayer activation.
- Canonical byte encoders, digest helpers, and committed payload fixtures are
  implemented for the exact inner payload structs.
- Exact role-envelope AAD fields, canonical AAD bytes, digest helpers, and
  expiry checks are implemented for encrypted signer-envelope framing.
- Initial Verus-friendly invariant notes are written for role separation,
  A/B peer direction, output-kind separation, transcript binding, signer-set
  policy, and host boundaries.
- Authority-verified fallback and normal-signing scopes are modeled separately
  from early prepare and A/B derivation setup.
- Phase 2 local boundary groundwork is started with typed Router,
  Signer A/Relayer, and Signer B endpoint descriptors, service-specific local
  binding guards, transport-neutral env snapshots, deterministic
  transcript-bound dev output packages, and route-checked local transport
  envelopes, plus deterministic in-process local handlers for Router dispatch,
  signer responses, A/B peer messages, and relayer activation delivery.
  Local startup configs now pair each handler with its validated role-specific
  env snapshot, and the in-process service stack can run the deterministic
  local ceremony from those startup configs. The typed local HTTP boundary and
  `dev:router-ab-signer` smoke command now exercise one client-to-Router
  request through Router, Signer A/Relayer, and Signer B, including local
  expiry and replay checks.
- Follow-up adapter refactor
  [docs/refactor-67-router-ab-threshold-prf-adapter.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/refactor-67-router-ab-threshold-prf-adapter.md)
  is written and started.
- `router-ab-core` now exposes an initial production
  `mpc_threshold_prf_v1` backend boundary over `threshold-prf`, including a
  Router/A/B-owned signing-root-share wire wrapper, signer proof-bundle
  evaluation, proof verification, and recipient-side verified combine.
- `threshold-prf` no longer enables `rand_core/getrandom` at the library layer,
  so the production backend dependency builds for both `wasm32-unknown-unknown`
  and `wasm32-wasip1` with explicit RNG injection.
- Focused backend tests now cover client-output combine, client/relayer output
  separation, wrong signer-share role, malformed share wire, invalid DLEQ proof,
  transcript mismatch, non-signer role, wrong root epoch, duplicate signer role,
  wrong recipient, and mixed-purpose combine rejection.
- Candidate A backend vectors are frozen in the generated contract corpus for
  registration, export, and refresh across client and relayer outputs, including
  partial wires, commitments, proofs, verified-combine outputs, and rejection
  cases.
- Local Router/A/B negative tests now cover wrong signer-role requests at
  signer handlers, peer messages presented as Router signer responses, and
  signer-response payload kinds presented as relayer activation material.
- `router-ab-core` now has a transport-neutral local persistence seed model
  for signing-root metadata and role-specific sealed-share records, with
  validation for signer set, root-share epoch, signer roles, distinct signer
  ids, storage keys, commitments, and sealed-share length.
- Local persistence seeds now produce validated parameterized SQL seed plans
  for Postgres and SQLite, with fixed bind ordering for root metadata,
  Signer A sealed shares, and Signer B sealed shares.
- `router-ab-core` now exposes a driver-neutral local SQL execution
  harness with typed receipts, so local Postgres or SQLite adapters can execute
  the seed plan without adding database drivers to the protocol crate.
- `crates/router-ab-dev` now provides a concrete SQLite seed adapter,
  schema creation, idempotent seed execution, read-back verification, and the
  `dev:router-ab-seed-sqlite` smoke command.
- `crates/router-ab-dev` now implements the protocol
  `SigningRootShareStore` boundary over seeded SQLite and exposes fail-closed
  startup checks for Signer A and Signer B root-share availability.
- The Router A/B Cloudflare adapter boundary is defined with Durable Object
  storage scopes, role-specific namespace visibility, and fail-closed startup
  rules. `crates/router-ab-cloudflare` is scaffolded with typed binding
  descriptors and constructor tests for Router, Signer A/Relayer, Signer B, and
  signer root-share startup checks.
- `crates/router-ab-cloudflare` now parses role-specific Cloudflare Env-reader
  input into typed binding descriptors, trims required values, rejects missing
  or empty required keys, and rejects forbidden Durable Object key families for
  Router, Signer A/Relayer, and Signer B.
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
  relayer-output activation.
- The Durable Object storage handler now has a feature-gated `workers-rs`
  fetch wrapper that rejects non-POST and wrong-path requests, parses the typed
  operation body, maps the configured Durable Object scope to the expected
  Worker role, and stores responses through Cloudflare `Storage`.
- `crates/router-ab-cloudflare` now has an initial thin Router Worker runtime
  context. It parses/validates Router startup bindings and can construct only
  Router-scoped Durable Object calls for replay reservation and public
  lifecycle state persistence.
- `router-ab-core` now defines `PublicRouterRequestV1`, a transport-neutral
  public request boundary that validates lifecycle scope, signer-set identity,
  selected relayer, expiry, nonce, and role-specific encrypted envelopes before
  producing canonical Router-to-Signer A and Router-to-Signer B wire messages.
- `crates/router-ab-cloudflare` now normalizes a validated public Router
  request plus trusted server-derived admission data into a
  `CloudflareRouterPublicAdmissionPlanV1`. The plan applies the gate decision
  to lifecycle state, reserves replay state, and only includes signer wire
  messages for accepted or reuse-existing decisions.
- `crates/router-ab-cloudflare` now has a feature-gated `workers-rs` public
  Router handler for `POST /v1/hss/split-derivation`. It reserves replay state,
  persists gate-applied public lifecycle state, forwards opaque role-specific
  signer wire messages over Cloudflare Service Bindings only after admission,
  and aggregates transcript-bound signer response wire messages.
- `crates/router-ab-cloudflare` now has thin Signer A/Relayer and Signer B
  private wrappers plus runtime contexts. The runtimes build only role-local
  root-share Durable Object calls, Signer A relayer-output activation calls,
  and the configured direct peer bindings.
- `crates/router-ab-cloudflare` now derives
  `CloudflareRouterTrustedAdmissionV1` from trusted Router metadata and
  Router-owned project policy, abuse, and quota check results. The derivation
  validates work kind, account id, and session id against the normalized public
  request before signer forwarding can be planned.
- `crates/router-ab-cloudflare` now verifies the public Router boundary with
  typed tests for auth context binding, project policy rejection, abuse
  throttling, quota saturation, request expiry, and replay reservation before
  signer forwarding.
- `crates/router-ab-cloudflare` now has a transport-neutral public Router plan
  executor for route-level tests. Rejected admission persists replay/lifecycle
  state without calling signer transports, and replayed requests stop before
  lifecycle persistence and signer forwarding.
- `crates/router-ab-cloudflare` now has Durable Object storage-surface tests
  proving Router lifecycle persistence serializes public lifecycle state while
  replay persistence carries only request id, expiry, and request digest
  material.
- `crates/router-ab-cloudflare` now has a preloaded synchronous signer host
  that implements the current core `SignerHost` trait set after async
  Cloudflare adapter code has loaded time, root-share metadata, peer responses,
  and randomness.
- `crates/router-ab-cloudflare` now has typed signer-host preload input, a
  native-tested preload builder, and feature-gated `workers-rs` functions that
  load signer-local root-share metadata from Durable Objects, capture Worker
  time, and fill bounded random buffers through Web Crypto-backed
  `getrandom`.
- `crates/router-ab-cloudflare` now has direct A/B peer endpoint validation,
  thin `workers-rs` peer fetch wrappers, and a Service Binding executor for
  `SignerAToSignerB` and `SignerBToSignerA` messages with transcript-bound
  opposite-direction responses.
- `crates/router-ab-cloudflare` now has a peer-request preload input and
  feature-gated `workers-rs` signer-host preload functions that execute direct
  A/B Service Binding calls before loading root metadata and randomness into
  `CloudflarePreloadedSignerHostV1`.
- `router-ab-core` now decodes canonical Router-to-signer payload bytes back
  into typed payloads, and the Cloudflare private signer endpoint rejects
  malformed payloads, wrong signer branches, and payload/wire transcript
  mismatches before handler execution.
- `router-ab-core` now validates Router-to-signer lifecycle/signer-set/relayer
  binding plus signer assignment identity before decoded payloads can reach a
  signer handler.
- Local Signer A/B handlers now decode Router-to-signer payloads and reject
  malformed payloads, transcript mismatches, wrong branches, and valid
  same-role payloads addressed to a different local signer identity before
  producing output.
- `crates/router-ab-core/specs/envelopes-and-delivery.md` now specifies the
  `signer_input` plaintext contract for the next decryption slice: public
  derivation metadata and output instructions only, strict decoding, no joined
  state fields, and signer-local root-share loading after plaintext checks.
- `router-ab-core` now implements `SignerInputPlaintextV1` with canonical
  bytes, a strict decoder, Candidate A-only validation, duplicate output
  rejection, selected-relayer binding, and trailing-byte rejection.
- `router-ab-core` now validates decoded signer-input plaintext against the
  Router-to-signer payload before signer work can use it, including lifecycle,
  signer-set, signer identity, relayer identity, transcript, Router request
  digest, AAD digest, and local root-share epoch binding.
- `router-ab-core` now has a Router boundary source guard preventing
  Router-facing protocol modules from importing signer-input plaintext decoder
  APIs.
- Local Signer A/B handlers now pass through a deterministic typed
  signer-envelope decryptor boundary before output generation. The local
  decryptor returns `SignerInputPlaintextV1`, then the handler validates it
  against the Router-to-signer payload, local Router request digest, and
  signer-local root-share epoch.
- `crates/router-ab-cloudflare` now has a post-decrypt signer-input plaintext
  validation boundary. Cloudflare signer adapters can feed decrypted bytes into
  `decode_and_validate_cloudflare_signer_input_plaintext_v1`, which decodes
  `SignerInputPlaintextV1` and binds it to the Router payload, Router request
  digest, AAD digest, root metadata role, signer identity, and root-share
  epoch.
- `crates/router-ab-cloudflare` now has a role-local signer-envelope AEAD
  key-source boundary. Signer startup bindings require public descriptors for
  the local Secret binding name and key epoch, `workers-rs` startup validation
  checks the configured Secret binding exists, and Router/Signer A/Signer B env
  parsing rejects envelope-key descriptors for roles that should not hold them.
- `router-ab-core` now specifies and implements a strict signer-envelope AEAD
  payload wrapper for the pre-decrypt boundary. It binds recipient role,
  envelope key epoch, AAD digest, 96-bit nonce, 128-bit tag length, and
  ciphertext/tag bytes, and rejects malformed, wrong-epoch, wrong-AAD, tag-only,
  or trailing-byte payloads before platform decryptors see them.
- `crates/router-ab-cloudflare` now validates signer-envelope AEAD public
  metadata before decryption against the Worker role, Router-to-signer
  assignment, and role-local envelope decrypt-key descriptor.
- `crates/router-ab-cloudflare` now has a feature-gated workers-rs
  AES-256-GCM WebCrypto decrypt boundary. It loads the role-local Cloudflare
  Secret binding as unpadded base64url 32-byte key material, imports it as a
  non-extractable decrypt-only key, decrypts with canonical role-envelope AAD,
  and can feed plaintext into the existing post-decrypt
  `SignerInputPlaintextV1` validator.
- `crates/router-ab-cloudflare` now has a narrow validated private signer
  request boundary for production signer engines. Future engine wrappers receive
  `CloudflareValidatedSignerPrivateRequestV1`, which contains only the
  role-checked Router-to-signer payload and already-validated
  `SignerInputPlaintextV1`; response transcript validation still runs after the
  handler returns.
- `router-ab-core` now rejects joined-state marker text in decoded
  `SignerInputPlaintextV1` public identifier fields and output recipient
  labels. This keeps the signer plaintext boundary limited to derivation
  metadata and output instructions while the real A/B engine wrapper is still
  pending.
- `router-ab-core` now has a required authenticated A/B peer-message envelope:
  canonical bytes-to-sign, sender and recipient signer identity binding,
  transcript binding, payload digest binding, signature scheme, and signature
  bytes. `crates/router-ab-cloudflare` decodes those peer payloads and rejects
  wire messages whose embedded direction, transcript, or authentication digest
  does not match the route.
- `router-ab-core` now exposes an Ed25519 verifier for authenticated A/B peer
  messages. The verifier checks the canonical bytes-to-sign against a
  sender-bound verifying key and rejects wrong-key signatures.
- Cloudflare signer-host preload guards now require direct A/B peer requests
  and responses to decode as authenticated peer-message payloads before
  synchronous engine code can consume them.
- `router-ab-core` signer hosts now expose signer-bound Ed25519 verifying-key
  access. `crates/router-ab-cloudflare` carries trusted verifying keys into
  preloaded signer hosts, verifies preloaded peer requests/responses before
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
  through Cloudflare Router-to-signer and direct A/B peer route validation.
- `crates/router-ab-cloudflare` now binds preloaded signer hosts to an
  expected signer role and rejects Durable Object root-share metadata for the
  opposite signer before constructing the host.
- `crates/router-ab-cloudflare` now has a feature-gated Signer A
  `workers-rs` relayer-output activation wrapper. It executes the typed
  relayer-output Durable Object call and accepts only the activation receipt
  response branch.
- `router-ab-core` now has a local Router opacity regression test: Router
  forwards kind-correct opaque signer payload bytes without decoding them, and
  malformed payloads are rejected only at the signer boundary.
- `router-ab-core` now has the strict recipient proof-bundle delivery unit:
  `RecipientProofBundlePayloadV1` plus
  `WireMessageKindV1::RecipientProofBundle`. The payload carries exactly one
  recipient-scoped proof bundle and rejects wrong recipient role, opened-share
  kind, signer identity, or transcript bindings before combine.
- `router-ab-core` now has `RecipientProofBundleCiphertextV1` plus a
  `RecipientProofBundleEncryptorV1` adapter boundary. The ciphertext header and
  AAD bind the producing signer identity, and core exposes a
  `recipient_proof_bundle` wire-message builder for final-recipient delivery.
  `router-ab-cloudflare` implements
  `CloudflareHpkeRecipientProofBundleEncryptorV1` and verifies HPKE round-trip
  opening back into the typed proof-bundle payload.
- `crates/router-ab-cloudflare` now has typed strict proof-bundle containers for
  private signer response, Router client-bundle aggregation, and Signer A
  relayer activation. These containers decode only public ciphertext envelope
  metadata and validate signer identity, recipient role, opened-share kind,
  recipient identity, recipient encryption key, and transcript digest against
  the Router payload.
- `crates/router-ab-cloudflare` now wires those strict containers through
  feature-gated `workers-rs` entrypoints: private signer proof-bundle routes,
  strict Router service aggregation, and the Signer A relayer proof-bundle
  activation route. The strict signer engine wrapper signs and validates the
  local proof batch, then returns only the local signer's encrypted client and
  relayer proof bundles.
- `crates/router-ab-cloudflare` now has an optional
  `strict-worker-entrypoint` feature that builds a `cdylib` Worker artifact,
  parses `ROUTER_AB_WORKER_ROLE` and `ROUTER_AB_ROUTE_PROFILE`, dispatches the
  strict Router proof-bundle route from a trusted-admission bootstrap body, and
  dispatches typed signer-private bootstrap bodies through the signer-host
  preload, decrypt, and strict proof-bundle path.
- `router-ab-core` now carries public `root_share_epoch` in
  `LifecycleScopeV1`, canonical Router-to-signer payload bytes, public Router
  request bytes, and committed payload vectors. This is the first concrete step
  toward the non-circular signer-envelope AAD and transcript digest redesign.
- `router-ab-core` now has `PublicRouterRequestContextV1` and
  `request_context_digest()`, a pre-envelope digest over public request context
  that excludes transcript digest, role-envelope AAD digests, and ciphertext.
  Signer plaintext fixtures now bind this context digest, while Router replay
  tests continue to use the full request digest.
- `router-ab-core` now has a pre-envelope derivation transcript path:
  `PublicRouterRequestContextV1::derivation_transcript_digest()` computes the
  transcript digest before signer-envelope encryption, `PublicRouterRequestV1`
  rejects mismatched transcript digests, and derivation `TranscriptBinding`
  no longer carries encrypted-envelope digests.
- `router-ab-core` now separates transcript metadata from envelope assignment
  metadata. `RouterTranscriptMetadataV1` carries public derivation context, and
  `RouterEnvelopeDigestSetV1` carries A/B encrypted-envelope digests used only
  for Router-to-signer assignment validation.
- `PublicRouterRequestV1::router_replay_digest()` now names the full-envelope
  Router replay/idempotency digest explicitly. Cloudflare Router admission uses
  it when reserving replay state, while signer AAD/plaintext continues to use
  the pre-envelope request-context digest.
- `crates/router-ab-cloudflare` now has
  `CloudflareSignerPrivateBootstrapRequestV1`, which carries the private
  Router-to-signer wire message, typed `RoleEnvelopeAadV1`, and pre-envelope
  request-context digest. It also has `CloudflareSignerHostPreloadPlanV1`,
  which derives signer-set id, root-share epoch, local signer identity,
  transcript digest, and request-context digest from that bootstrap body before
  host preload.
- The strict Worker signer routes now parse typed signer-private bootstrap
  bodies, validate role-envelope AAD, derive the signer-host preload plan, and
  validate trusted A/B peer verifying keys from role-local Worker config.
- Router A/B v1 strict proof-bundle delivery now uses independent Router
  dispatch to Signer A and Signer B. Each signer produces only local
  recipient-scoped proof bundles; Router aggregation requires both signer
  responses for liveness.
- The strict Worker Signer A/Relayer and Signer B private routes now invoke the
  signer-host preload, signer-envelope decrypt, root-share wire, peer signing
  key, and strict proof-bundle handler path end to end.
- Role-specific release Wasm, `wasm-opt`, and Wrangler dry-run packaging size
  measurements are recorded. Cloudflare runtime `startup_time_ms` and
  production deployment evidence still need release-candidate data.
- `crates/router-ab-cloudflare` now exposes workers-rs Durable Object classes
  for Router replay, Router lifecycle, Signer A root-share, Signer A relayer
  output, and Signer B root-share storage. The per-role Wrangler configs now
  declare those classes, migrations, Service Bindings, role-local Env names,
  and secret binding-name variables.
- `crates/router-ab-cloudflare` now has a focused Wasm vector test script:
  `pnpm -C crates/router-ab-cloudflare test:wasm-vectors`. It runs the
  committed wire and payload vectors under Node with the workers-rs Router
  entrypoint feature enabled.
- `crates/router-ab-cloudflare` now has a typed Router admission-provider
  boundary. Auth/session, project policy, abuse, and quota providers return
  `CloudflareRouterAdmissionProviderOutputV1`; Router derives
  `CloudflareRouterTrustedAdmissionV1` from that provider-owned output.
- `crates/router-ab-cloudflare` now has `benches/router_latency.rs`, which
  records a native CPU baseline for Router admission plus simulated A/B
  coordination over 1, 2, 3, and 4 local round trips.

Immediate next steps:

1. Implement concrete Router JWT/session, project policy, quota, and abuse
   providers behind `CloudflareRouterAdmissionProviderV1`.
2. Benchmark normal signing latency and deployed or Wrangler-profiled
   setup/export latency.
3. Capture Cloudflare Worker runtime latency evidence from a deployed or
   wrangler-profiled strict Worker.
4. Replace Wrangler verifying-key placeholders and provision Cloudflare secrets
   for each signer role before any production deploy.
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
- [x] Define the minimum transcript binding fields for signer identity and
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
  - [x] Add initial encrypted signer-envelope wrappers.
  - [x] Add initial canonical wire-message wrappers.
- [x] Keep `router-ab-core` free of Cloudflare APIs, filesystem APIs,
  ambient time, ambient randomness, and transport dependencies.
- [x] Define `router-ab-core/src/protocol/engine` with Router, Signer A,
  Signer B, relayer activation, and host-trait modules.
- [x] Define host traits inside `router-ab-core` for clock, randomness,
  signer keys, signing-root share storage, peer transport, and audit sinks.
- [x] Define canonical request/response bytes for Router-to-A, Router-to-B,
  A-to-B, B-to-A, signer responses, and relayer activation.
  - [x] Add initial versioned, length-prefixed `WireMessageV1` canonical bytes
        and digest helper.
  - [x] Define exact service payload structs for Router-to-signer, A/B peer
        messages, signer responses, and relayer activation.
  - [x] Add canonical encoders for exact service payload structs.
  - [x] Add committed fixtures for exact service payload structs.
- [x] Add cross-host wire vectors so Rust native, Rust/Wasm, and TypeScript
  hosts can verify the same transcript bytes.
- [x] Define role-specific Router, A, B, client-output, and relayer-output
  types.
- [x] Model Router A/B v1 around a signer-set and indexed role-envelope shape,
  while enforcing an `all(2)` quorum policy for the first release.
- [x] Define encrypted envelope framing with transcript-bound associated data.
  - [x] Add first role-encrypted envelope wrapper with header and AAD digests.
  - [x] Define exact role-envelope AAD fields and canonical AAD digest helper.
  - [x] Resolve non-circular canonical bytes for signer-envelope AAD,
        transcript digest, and Router replay digest.
        - [x] Add public root-share epoch to Router request scope.
        - [x] Add pre-envelope request-context digest for AAD/plaintext.
        - [x] Add pre-envelope derivation transcript digest for HSS/output
              bindings.
        - [x] Keep full-envelope replay digest scoped to Router storage.
        - [x] Add strict signer bootstrap body carrying typed AAD from Router.
- [x] Define signer identities and key rotation rules.
- [x] Add type fixtures rejecting invalid branch combinations.
  - [x] Add constructor tests for invalid gate branches, lifecycle scope,
        signer-set roles, duplicate signer ids, envelope role mismatch, and
        output package recipient semantics.
- [x] Add source guards for forbidden imports in Router and signer code.
- [x] Add initial Verus-friendly invariant notes for role separation,
  output-kind separation, and transcript binding.

### Phase 2: Local Boundary Simulation

- [x] Add local service entrypoints for Router, Signer A/Relayer, and Signer B.
  - [x] Add protocol-level local endpoint descriptors for Router,
        Signer A/Relayer, and Signer B.
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
  - [x] Wire seeded SQLite persistence into local signer startup or host-store
        checks.
- [x] Add deterministic transcript-bound dev output shares for boundary tests.
- [x] Add local HTTP transport for Router-to-signer and A-to-B coordination.
  - [x] Add route-checked local transport envelopes for Router-to-signer,
        signer-to-Router, A-to-B, B-to-A, and B-to-Signer-A-relayer delivery.
  - [x] Add executable in-process handlers on top of the checked envelopes.
  - [x] Add typed local HTTP handlers on top of the checked envelopes.
- [x] Add a `dev:router-ab-signer` script that starts the full local stack.
- [x] Add end-to-end local tests that send one client request to the Router and
  verify encrypted A/B package delivery.
- [x] Add negative local Router/A/B tests for wrong-role payloads and
  output-kind confusion.
  - [x] Add in-process local test covering Router dispatch, Signer A/B
        responses, A/B peer messages, and relayer activation routing.
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
  - [x] Add Router opacity test proving malformed opaque signer payloads are
        forwarded by Router and rejected at the signer boundary.

### Phase 3: Router Boundary

- [x] Create `crates/router-ab-cloudflare` with typed Cloudflare Durable Object
      storage scopes, role-specific binding descriptors, and startup-check
      descriptors.
- [x] Add typed Env-reader parsing behind the Cloudflare binding descriptors.
- [x] Add the optional `worker::Env` bridge and real binding-presence checks.
- [x] Add typed Durable Object call execution for replay reservations, public
      lifecycle state, root-share startup checks, and relayer-output activation.
- [x] Implement Router Durable Object handler storage for replay reservations
      and public lifecycle state.
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
- [ ] Wire real JWT/session, project policy, quota, and abuse providers into
  the trusted admission derivation boundary.
- [x] Add the Router-owned expensive-work admission gate before signer
  forwarding.
- [x] Derive gate context from trusted Router metadata, never from client
  JSON.
- [x] Implement accepted, reuse-existing, defer, and rejected gate decisions.
- [x] Add route tests proving rejected requests do not reach Signer A, Signer B,
  or HSS prepare.
- [x] Forward A/B encrypted envelopes without decrypting them.
- [x] Persist only public lifecycle state and payload hashes.
- [x] Aggregate encrypted client packages into one response.

### Phase 4: Signer A/B Services

- [x] Implement Signer A/B Durable Object handler storage for root-share startup
      checks and relayer-output activation.
- [x] Add thin `workers-rs` Signer A and Signer B wrappers around the
  platform-agnostic signer engines.
- [x] Add Signer A/Relayer and Signer B runtime contexts around validated
  Cloudflare bindings.
- [x] Add a preloaded synchronous Cloudflare signer host that implements the
  current core host traits.
- [x] Wire workers-rs async preload from Env, Durable Objects, and randomness
  into the preloaded signer host.
- [x] Add the direct A/B peer service-binding endpoint.
- [x] Wire direct A/B peer-response preload into the preloaded signer host.
- [x] Add private A and B signer endpoints.
- [ ] Decrypt only role-specific envelopes.
  - [x] Decode and role-check Router-to-signer payloads before signer output.
  - [x] Require payload signer assignment to match signer-set and local signer
        identity.
  - [x] Specify the `signer_input` plaintext schema and strict rejection rules.
  - [x] Implement the `SignerInputPlaintextV1` canonical decoder.
  - [x] Validate decoded signer-input plaintext against Router-to-signer
        payload, Router request digest, and local root-share epoch.
  - [x] Add a deterministic local signer-envelope decryptor boundary that
        returns typed signer input plaintext.
  - [x] Add the Cloudflare post-decrypt signer-input plaintext validation
        boundary for production adapters.
  - [x] Add role-local Cloudflare signer-envelope AEAD key-source descriptors
        and startup validation.
  - [x] Specify and implement strict signer-envelope AEAD payload parsing for
        the pre-decrypt boundary.
  - [x] Validate Cloudflare signer-envelope AEAD public metadata against the
        Worker role and role-local key descriptor before decryption.
  - [x] Wire feature-gated workers-rs AES-256-GCM WebCrypto decryption into
        that boundary.
  - [x] Add a narrow validated private signer request boundary for production
        signer-engine wrappers.
  - [x] Wire the real private signer engine wrapper through the Cloudflare
        decrypt-then-validate boundary.
    - [x] Promote or add a platform-neutral builder from
          `RouterToSignerPayloadV1` plus `SignerInputPlaintextV1` into
          `MpcPrfThresholdSignerBatchInputV1`.
    - [x] Add a production root-share wire source to the Cloudflare signer host.
      - [x] Add redacted preloaded root-share wire records and a role-local
            host accessor for deterministic production-adapter tests.
      - [x] Add a versioned lower-hex root-share wire secret decoder that
            returns only the redacted role-local preloaded record.
      - [x] Add role-local Cloudflare root-share wire Secret binding
            descriptors and Env parsing.
      - [x] Load the role-local root-share wire from the selected Cloudflare
            Secret binding path, validate it against startup metadata, and
            return only the redacted preloaded record.
      - [x] Wire async Cloudflare signer-host preload to attach the validated
            role-local root-share wire Secret to the synchronous signer host.
      - [ ] Add a sealed Durable Object or KMS-backed storage path if
            production rotations need runtime unsealing beyond Cloudflare
            Secret binding rotation.
    - [x] Add Signer A and Signer B validated handlers that run
          `SignerAEngine`/`SignerBEngine`, authenticate A/B proof-batch
          messages, combine threshold outputs, and use
          `CloudflareHpkeRecipientOutputEncryptorV1` for recipient delivery.
      - [x] Promote shared A/B proof-batch combine plus recipient-output
            packaging so local dev and Cloudflare use the same transcript and
            package-commitment logic.
      - [x] Add a Cloudflare validated MPC PRF engine bridge that turns a
            decrypt-validated signer request plus role-local root-share wire
            into a real `SignerAEngine`/`SignerBEngine` proof batch.
      - [x] Add shared Cloudflare proof-batch peer-message helpers that sign
            local proof batches, verify/decode authenticated peer proof batches,
            combine A/B outputs, and build canonical signer responses.
      - [x] Add a synchronous Cloudflare validated MPC PRF signer handler that
            evaluates the local proof batch, sends the signed peer proof batch
            through host transport, combines verified A/B outputs, and returns
            `SignerResponsePayloadV1`.
      - [x] Add a testable peer signing-key/request binding check for Worker
            role, signer identity, and signer key epoch before loading the
            secret signing key bytes.
      - [x] Wire the workers-rs wrapper to load the role-local peer signing key
            Secret, call the synchronous validated MPC PRF handler, and pass
            `CloudflareHpkeRecipientOutputEncryptorV1` for production delivery.
      - [x] Connect the production private fetch/bootstrap path to
            recipient-scoped MPC PRF proof-batch delivery once the deployable
            Worker entrypoint supplies role-envelope AAD, Router request digest,
            root-share metadata, and root-share wire.
        - [x] Resolve the production A/B orchestration shape before exposing
              this as a deployable signer route: strict server-blind production
              uses recipient-side combine, and signer-side combine remains a
              preloaded test or weaker deployment profile.
        - [x] Add core recipient-scoped proof-batch views so client delivery can
              carry only `x_client_base` proof bundles and relayer delivery can
              carry only `x_relayer_base` proof bundles.
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
                Cloudflare HPKE encryption for client or designated relayer
                recipient keys.
          - [x] Add typed strict Cloudflare private signer response, Router
                client-bundle aggregation, and Signer A relayer activation
                containers around encrypted recipient proof-bundle payloads.
          - [x] Wire the strict containers through `workers-rs` private signer,
                Router aggregation, and Signer A relayer activation entrypoints.
          - [x] Add a deployable Worker bootstrap scaffold that chooses the
                strict proof-bundle route profile and dispatches the trusted
                Router route.
          - [x] Add strict private-bootstrap-to-signer-host preload plan
                derivation before signer-host execution.
          - [x] Add a deployable trusted A/B verifying-key provider for the
                strict signer-host preload input.
          - [x] Decide the deployable live peer-coordination shape:
                independent Router dispatch to A and B, with Router
                aggregation requiring both signer responses for liveness.
          - [x] Scope async direct A/B peer coordination to signer-side combine,
                rendezvous, or later hardening profiles outside v1 strict
                proof-bundle delivery.
          - [x] Wire deployable Signer A/Relayer and Signer B private route
                bootstraps to the signer-host preload provider.
      - [x] Promote shared MPC PRF combined-output packaging so local dev and
            Cloudflare adapters use the same package commitment logic with
            adapter-specific recipient encryption.
      - [x] Specify and bind the selected relayer recipient encryption key in
            `RelayerIdentityV1`, signer-set canonical bytes, and transcript
            digests for HPKE relayer delivery.
- [x] Verify transcript binding and signer role.
- [x] Load only signer-local root material.
- [x] Reject any payload that contains joined state.
  - [x] Strict `SignerInputPlaintextV1` decoding rejects unknown/trailing
        plaintext bytes.
  - [x] Guard Router-facing protocol modules against signer plaintext decoder
        imports.
  - [x] Reject Router-to-signer payloads for the wrong signer role.
  - [x] Reject joined-state marker text in signer plaintext identifier fields
        and output recipient labels.
- [x] Add direct A/B mutual authentication.
  - [x] Add a canonical A/B peer authentication input and required signature
        carrier to `AbPeerMessagePayloadV1`.
  - [x] Decode Cloudflare peer payloads before handler execution and reject
        sender/recipient direction, transcript, or authentication-digest
        mismatches.
  - [x] Require authenticated peer-message payloads in Cloudflare signer-host
        preloaded peer request/response inputs.
  - [x] Add a core Ed25519 verifier for authenticated A/B peer payloads.
  - [x] Extend signer host key access with trusted signer verifying keys.
  - [x] Verify Ed25519 peer request signatures before handler execution.
  - [x] Verify preloaded peer request/response signatures before synchronous
        engine execution.
  - [x] Add local peer signing-key access for outbound A/B messages.
  - [x] Add production Cloudflare signing-key loading for outbound A/B
        messages.
  - [x] Run the same wire and payload vectors through Cloudflare adapter
        boundary tests.

### Phase 5: Direct A/B Protocol

- [ ] Implement the split derivation primitive selected by Phase 0A.
  - [x] Add the selected `mpc_threshold_prf_v1` signer batch-evaluation
        backend for all requested signer outputs.
  - [x] Wire the batch evaluator into platform-agnostic signer engines.
- [x] Implement A/B protocol message types with transcript-bound signatures.
  - [x] Add a canonical `AbDerivationProofBatchPayloadV1` carrying
        threshold-PRF proof bundles under the authenticated A/B peer envelope.
  - [x] Validate inner proof-batch sender, recipient, transcript, root epoch,
        and proof-bundle bindings against the signed peer envelope.
- [x] Ensure messages carry only protocol-safe material.
  - [x] Add source guards preventing A/B peer payload modules from importing
        combined outputs, root-share wires, or raw secret material.
- [x] Produce A/B shares of client and relayer outputs.
  - [x] Signer engines produce threshold-PRF proof bundles for both
        `x_client_base` and `x_relayer_base`.
  - [x] Add a signer-identity-checked builder that signs those proof bundles
        into authenticated A/B peer payloads.
  - [x] Add a recipient-side batch combiner that verifies matching A/B proof
        bundles and produces combined client and relayer output material.
- [x] Keep A/B round trips within the target budget.
  - [x] Record and test the current adapter round-trip profile: one
        Router-facing client request, one Router invocation, one Signer A
        invocation, one Signer B invocation, and zero modeled direct A/B
        coordination round trips per ceremony.

### Phase 6: Output Delivery

- [ ] Encrypt A and B client-output packages directly to the client ephemeral
  key.
  - [x] Public Router requests now require a client ephemeral public key, and
        the key is bound into the derivation transcript digest and
        Router-to-signer payload metadata.
  - [x] Output packages now carry a typed recipient-output ciphertext envelope
        binding algorithm, recipient role, opened share kind, recipient
        identity, recipient encryption key, transcript digest, and package
        commitment.
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
  - [ ] Add deterministic seal vectors and a Wasm vector pass for
        `hpke_x25519_hkdf_sha256_aes256gcm_v1`.
  - [ ] Verify AES-256-GCM constant-time posture for the Cloudflare Wasm target
        before production use. If this cannot be established, define a
        ChaCha20-Poly1305 HPKE suite as a new protocol algorithm.
  - [ ] Replace local placeholder output ciphertext with recipient-key
        encryption.
- [ ] Deliver relayer-output packages only to the designated relayer.
  - [x] `SignerResponsePayloadV1` now carries only the client-output package;
        `RelayerActivationPayloadV1` is the only canonical payload that carries
        relayer-output delivery material.
- [x] Add client-side verification for matching transcript and output kind.
  - [x] `verify_client_output_package_v1` checks the expected transcript and
        enforces the client `x_client_base` package type before opening.
- [x] Add relayer-side verification for matching transcript and output kind.
  - [x] `verify_relayer_output_package_v1` checks the expected transcript and
        enforces the relayer `x_relayer_base` package type before opening.
- [x] Add downgrade rejection for clients requiring split derivation.
  - [x] Public Router requests now carry a required derivation candidate, and
        v1 rejects anything other than `mpc_threshold_prf_v1` before signer
        payloads are created.

### Phase 7: Normal Signing Integration

- [x] Add relayer activation handling to the Signer A `workers-rs` wrapper.
- [ ] Keep the optional separate Relayer wrapper as a later split if deployment
  boundaries require it.
- [ ] Store or activate `x_relayer_base` only in Signer A's relayer state for
  the initial deployment.
- [ ] Keep normal signing on the Router plus active relayer path.
- [ ] Ensure normal signing routes cannot invoke A/B derivation paths
  accidentally.
- [ ] Add operational controls for relayer-share refresh.

### Phase 8: Local Cryptographic Simulation

- [x] Replace deterministic dev output shares with the selected split derivation
  primitive.
  - [x] Local in-process ceremonies now combine signed A/B threshold-PRF proof
        batches into threshold-derived client and relayer output packages before
        Router response collection and relayer activation.
  - [x] Signer handlers now emit only authenticated A/B proof-batch peer
        messages. Local Router responses and relayer activation are built after
        both proof batches are combined.
- [ ] Wire threshold-PRF partial evaluation or the selected split root
  derivation into local A/B services.
  - [x] Replace opaque local A/B peer-message bodies with signed
        threshold-PRF proof-batch peer payloads.
  - [x] Carry or reconstruct the production transcript binding at the local
        signer boundary, including network id, account public key, Router id,
        client id, and separate encrypted-envelope assignment digests.
        `RouterTranscriptMetadataV1` and `RouterEnvelopeDigestSetV1` now ride
        inside each Router-to-signer payload, and local signer proof-batch
        generation rejects reconstructed transcript digest mismatches before
        threshold-PRF evaluation.
- [ ] Wire split `y_relayer` and `tau_relayer` material into the local A/B HSS
  derivation protocol.
- [ ] Add local address and public-key parity tests.
- [ ] Add local root-share refresh tests proving wallet identity is preserved.
- [ ] Verify no local process materializes joined `d`, `a`, or
  `x_client_base`.

### Phase 9: Validation And Benchmarks

- [x] Add tests for Router opacity.
- [x] Add tests for wrong-role signer payload rejection.
- [x] Add tests for transcript mismatch, replay, expiry, and wrong relayer.
- [x] Add tests proving no joined state crosses production route boundaries.
  - [x] Add a Cloudflare source guard preventing production adapter code from
        importing or calling recipient-side threshold output combine paths.
- [x] Add native Rust tests for platform-agnostic signer engines without
  Cloudflare dependencies.
- [x] Add Wasm tests proving the same canonical wire vectors pass through the
  `workers-rs` adapters.
  - [x] Add `tests/wasm_vector_adapters.rs` and
        `pnpm -C crates/router-ab-cloudflare test:wasm-vectors`.
- [ ] Add optional TypeScript compatibility tests that parse and verify the
  canonical wire protocol.
- [x] Record compressed and uncompressed release Wasm size for Router,
  Signer A/Relayer, and Signer B.
  - [x] Record combined strict Worker role-dispatch artifact size:
        2,370,450 bytes uncompressed, 671,138 bytes gzip.
  - [x] Record role-specific strict Worker release Wasm sizes:
        Router 1,836,346 bytes uncompressed / 487,682 bytes gzip;
        Signer A/Relayer 2,126,483 / 614,303;
        Signer B 1,990,085 / 577,469.
  - [x] Record Wrangler-bundled and `wasm-opt` sizes for each role:
        Router 1088.52 KiB / gzip 381.52 KiB;
        Signer A/Relayer 1340.19 KiB / gzip 497.55 KiB;
        Signer B 1273.60 KiB / gzip 478.68 KiB.
- [ ] Record Wrangler `startup_time_ms` for every Rust/Wasm Worker.
  - [x] Record current blocked state: Wrangler `startup_time_ms` requires
        deployed or Wrangler-profiled role Worker bundles.
- [ ] Benchmark setup/export latency with 1, 2, 3, and 4 A/B round trips.
  - [x] Add and run native Router adapter CPU benchmark:
        1 round trip 62.882 us; 2 round trips 82.568 us;
        3 round trips 102.72 us; 4 round trips 123.85 us.
- [ ] Benchmark normal signing latency to confirm it remains close to the
  current single-relayer path.

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

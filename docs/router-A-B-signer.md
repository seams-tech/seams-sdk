# Router A/B Signer Architecture Plan

Date created: June 11, 2026

Status: design plan.

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

The designated relayer may be Signer A, Signer B, or a separate service. If A is
also the relayer, B may send relayer-output material to A, but B must encrypt
B-side client-output material directly to the client.

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
- envelope hashes
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
Signer A Worker: private/internal endpoint
Signer B Worker: private/internal endpoint
Relayer Worker: normal signing endpoint
```

For stronger operational separation, A and B can live in separate Cloudflare
accounts and communicate over authenticated HTTPS. That adds real network
latency but improves independence.

For lower latency, same-account Service Bindings can connect Workers with very
low overhead. That improves performance but weakens the independent-account
trust boundary. Use this only if the security target accepts one Cloudflare
account as the operational boundary.

## Operational Roadmap

The protocol should be designed as separate trust domains from day one, even
when the first deployment runs entirely inside one Cloudflare account. That
keeps the initial implementation cheap and simple while preserving a path to
stronger operational separation.

### Stage 1: Single Cloudflare Account Prototype

```text
Cloudflare account 1:
  Router Worker
  Signer A Worker
  Signer B Worker
  Relayer Worker
  same-account Service Bindings
```

This stage optimizes for development speed, low latency, and operational
simplicity. It should validate:

- role-specific encrypted envelopes
- Router opacity
- A-only and B-only plaintext boundaries
- direct A/B protocol behavior
- client-output encryption
- relayer-output delivery
- setup/export/refresh latency
- normal signing latency through Router plus one relayer

Even in this stage, the Router must see only ciphertext and public metadata.
Signer A and Signer B must use the same role-specific APIs that a future
multi-account or multi-cloud deployment would use.

### Stage 2: Separate Cloudflare Accounts

```text
Cloudflare account 1:
  Router Worker

Cloudflare account 2:
  Signer A Worker

Cloudflare account 3:
  Signer B Worker

optional Cloudflare account 4:
  Relayer Worker
```

This stage increases operational separation while keeping the same provider and
deployment model. It adds:

- separate Cloudflare account credentials
- separate deploy tokens
- separate secrets and signer keys
- separate logs and alerting
- authenticated HTTPS between Router, A, B, and relayer
- stronger blast-radius reduction for control-plane compromise

The protocol should not change at this stage. The transport changes from
same-account Service Bindings to authenticated cross-account HTTPS, and the
signer identity registry should pin the expected public keys for A, B, Router,
and relayer.

### Stage 3: Multi-Cloud TEE Signers

```text
Cloudflare:
  Router Worker

AWS:
  Signer A on Nitro Enclave-backed service

Google Cloud:
  Signer B on Confidential VM/service

Cloudflare or hardened service:
  Relayer
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
deployment. The first useful shape is four local services plus local durable
state:

```text
localhost:8787  Router
localhost:8788  Signer A
localhost:8789  Signer B
localhost:8790  Relayer
local Postgres  signing-root metadata and sealed-share records
```

Each service should run as its own process with its own environment file and
role-specific secrets:

```text
router.env:
  ROUTER_SIGNING_KEY
  SIGNER_A_URL
  SIGNER_B_URL
  RELAYER_URL
  no share decrypt keys

signer-a.env:
  SIGNER_ROLE=A
  SIGNER_A_DECRYPT_KEY
  SIGNING_ROOT_SHARE_A_KEK
  SIGNER_B_URL

signer-b.env:
  SIGNER_ROLE=B
  SIGNER_B_DECRYPT_KEY
  SIGNING_ROOT_SHARE_B_KEK
  SIGNER_A_URL

relayer.env:
  RELAYER_DECRYPT_KEY
  RELAYER_OUTPUT_STORAGE
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
- run Router, Signer A, Signer B, and Relayer as separate processes
- generate deterministic dev output shares from transcript-bound test vectors
- send one client request to the Router containing encrypted A and B envelopes
- have Router forward opaque envelopes without decrypting them
- have A and B decrypt only their own envelopes
- have A and B coordinate directly over local HTTP
- return encrypted client-output packages through the Router
- deliver relayer-output packages only to the local relayer
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

Add a single command or script that starts the full local simulation stack:

```text
dev:router-ab-signer
```

That command should:

- verify local Postgres is reachable
- seed or verify signing-root metadata
- seed or verify role-specific sealed-share records
- allocate service ports
- write or load service-specific dev env files
- start Router, Signer A, Signer B, and Relayer
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
  Signer A Worker HTTP entrypoint
  Signer B Worker HTTP entrypoint
  Relayer Worker HTTP entrypoint
  Cloudflare Env bindings
  fetch/service-binding transport adapters
  response mapping

TypeScript:
  optional build/test harness glue
  optional host implementation using the same canonical wire protocol
  optional Wasm/npm consumer of the Rust protocol core
```

Router, Signer A, Signer B, and Relayer may all be Rust Workers. The protocol
boundary should still use portable request/response envelopes rather than
Cloudflare-specific object RPC:

```text
Router -> Signer A: request carrying encrypted A envelope
Router -> Signer B: request carrying encrypted B envelope
A <-> B: request carrying transcript-bound protocol messages
Router -> Relayer: request carrying relayer-output package
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

Start with two crates. Keep the design modular inside `router-ab-protocol`, and
split out more crates only when module size or dependency boundaries require
it.

```text
crates/router-ab-protocol
  pure protocol types
  canonical wire encoding
  transcript state machines
  envelope framing
  platform-agnostic signer engines
  relayer activation engine
  host traits

crates/router-ab-cloudflare
  thin workers-rs adapters, Env parsing, fetch/service adapters

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

`router-ab-protocol` should avoid Cloudflare APIs, filesystem APIs, ambient
time, ambient randomness, and broad async dependencies. Boundary adapters should
inject time, randomness, peer identities, and transport.

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
crates/router-ab-protocol/
  Cargo.toml
  src/
    lib.rs
    error.rs
    ids.rs
    roles.rs

    wire/
      mod.rs
      canonical.rs
      requests.rs
      responses.rs
      envelopes.rs

    transcript/
      mod.rs
      digest.rs
      bindings.rs

    engine/
      mod.rs
      router.rs
      signer_a.rs
      signer_b.rs
      relayer.rs
      host.rs

    output/
      mod.rs
      client.rs
      relayer.rs

    crypto/
      mod.rs
      aead.rs
      keys.rs
      rng.rs

    test_vectors.rs

  tests/
    wire_vectors.rs
    role_boundaries.rs
    transcript_binding.rs
    output_kind.rs

crates/router-ab-cloudflare/
  Cargo.toml
  src/
    lib.rs
    env.rs
    request.rs
    response.rs

    router_worker.rs
    signer_a_worker.rs
    signer_b_worker.rs
    relayer_worker.rs

    host/
      mod.rs
      clock.rs
      keys.rs
      storage.rs
      transport.rs
      audit.rs
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
- keep Router, Signer A, Signer B, and Relayer as separate Workers so each
  bundle carries only its role's code
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

## Implementation Plan

### Phase 1: Protocol Types And Invariants

- [ ] Create a pure Rust `router-ab-protocol` crate for role-specific protocol
  types, state machines, transcript binding, envelope framing, engines, and
  host traits.
- [ ] Keep `router-ab-protocol` free of Cloudflare APIs, filesystem APIs,
  ambient time, ambient randomness, and transport dependencies.
- [ ] Define `router-ab-protocol/src/engine` with Router, Signer A, Signer B,
  Relayer, and host-trait modules.
- [ ] Define host traits inside `router-ab-protocol` for clock, randomness,
  signer keys, signing-root share storage, peer transport, and audit sinks.
- [ ] Define canonical request/response bytes for Router-to-A, Router-to-B,
  A-to-B, B-to-A, signer responses, and relayer activation.
- [ ] Add cross-host wire vectors so Rust native, Rust/Wasm, and TypeScript
  hosts can verify the same transcript bytes.
- [ ] Define role-specific Router, A, B, client-output, and relayer-output
  types.
- [ ] Define encrypted envelope framing with transcript-bound associated data.
- [ ] Define signer identities and key rotation rules.
- [ ] Add type fixtures rejecting invalid branch combinations.
- [ ] Add source guards for forbidden imports in Router and signer code.
- [ ] Add initial Verus-friendly invariant notes for role separation,
  output-kind separation, and transcript binding.

### Phase 2: Local Boundary Simulation

- [ ] Add local service entrypoints for Router, Signer A, Signer B, and
  Relayer.
- [ ] Add service-specific local env loading with forbidden-key checks.
- [ ] Add local Postgres seeding for signing-root metadata and role-specific
  sealed-share records.
- [ ] Add deterministic transcript-bound dev output shares for boundary tests.
- [ ] Add local HTTP transport for Router-to-signer and A-to-B coordination.
- [ ] Add a `dev:router-ab-signer` script that starts the full local stack.
- [ ] Add end-to-end local tests that send one client request to the Router and
  verify encrypted A/B package delivery.
- [ ] Add negative local tests for Router plaintext access, wrong-role payloads,
  replay, expiry, transcript mismatch, and output-kind confusion.

### Phase 3: Router Boundary

- [ ] Add a thin `workers-rs` Router wrapper around `router-ab-protocol`.
- [ ] Add the public split-derivation route.
- [ ] Parse and normalize public request metadata once.
- [ ] Verify auth, project policy, quota, abuse controls, expiry, and replay
  window.
- [ ] Add the Router-owned expensive-work admission gate before signer
  forwarding.
- [ ] Derive gate context from trusted Router metadata, never from client JSON.
- [ ] Implement accepted, reuse-existing, defer, and rejected gate decisions.
- [ ] Add route tests proving rejected requests do not reach Signer A, Signer B,
  or HSS prepare.
- [ ] Forward A/B encrypted envelopes without decrypting them.
- [ ] Persist only public lifecycle state and payload hashes.
- [ ] Aggregate encrypted client packages into one response.

### Phase 4: Signer A/B Services

- [ ] Add thin `workers-rs` Signer A and Signer B wrappers around the
  platform-agnostic signer engines.
- [ ] Implement `CloudflareSignerHost` for Env parsing, signer keys,
  signing-root share access, peer transport, and audit sinks.
- [ ] Add private A and B signer endpoints.
- [ ] Decrypt only role-specific envelopes.
- [ ] Verify transcript binding and signer role.
- [ ] Load only signer-local root material.
- [ ] Reject any payload that contains joined state or the wrong role.
- [ ] Add direct A/B mutual authentication.

### Phase 5: Direct A/B Protocol

- [ ] Choose the two-party HSS/MPC primitive for split derivation.
- [ ] Implement A/B protocol message types with transcript-bound signatures.
- [ ] Ensure messages carry only protocol-safe material.
- [ ] Produce A/B shares of client and relayer outputs.
- [ ] Keep A/B round trips within the target budget.

### Phase 6: Output Delivery

- [ ] Encrypt A and B client-output packages directly to the client ephemeral
  key.
- [ ] Deliver relayer-output packages only to the designated relayer.
- [ ] Add client-side verification for matching transcript and output kind.
- [ ] Add relayer-side verification for matching transcript and output kind.
- [ ] Add downgrade rejection for clients requiring split derivation.

### Phase 7: Normal Signing Integration

- [ ] Add a thin `workers-rs` Relayer wrapper around the platform-agnostic
  relayer activation engine.
- [ ] Store or activate `x_relayer_base` only in the designated relayer state.
- [ ] Keep normal signing on the Router plus active relayer path.
- [ ] Ensure normal signing routes cannot invoke A/B derivation paths
  accidentally.
- [ ] Add operational controls for relayer-share refresh.

### Phase 8: Local Cryptographic Simulation

- [ ] Replace deterministic dev output shares with the selected split derivation
  primitive.
- [ ] Wire threshold-PRF partial evaluation or the selected split root
  derivation into local A/B services.
- [ ] Wire split `y_relayer` and `tau_relayer` material into the local A/B HSS
  derivation protocol.
- [ ] Add local address and public-key parity tests.
- [ ] Add local root-share refresh tests proving wallet identity is preserved.
- [ ] Verify no local process materializes joined `d`, `a`, or
  `x_client_base`.

### Phase 9: Validation And Benchmarks

- [ ] Add tests for Router opacity.
- [ ] Add tests for wrong-role signer payload rejection.
- [ ] Add tests for transcript mismatch, replay, expiry, and wrong relayer.
- [ ] Add tests proving no joined state crosses production route boundaries.
- [ ] Add native Rust tests for platform-agnostic signer engines without
  Cloudflare dependencies.
- [ ] Add Wasm tests proving the same canonical wire vectors pass through the
  `workers-rs` adapters.
- [ ] Add optional TypeScript compatibility tests that parse and verify the
  canonical wire protocol.
- [ ] Record compressed and uncompressed Worker size for Router, Signer A,
  Signer B, and Relayer.
- [ ] Record Wrangler `startup_time_ms` for every Rust/Wasm Worker.
- [ ] Benchmark setup/export latency with 1, 2, 3, and 4 A/B round trips.
- [ ] Benchmark normal signing latency to confirm it remains close to the
  current single-relayer path.

## Open Decisions

- Which two-party HSS/MPC primitive should implement the A/B derivation?
- Is the designated relayer Signer A, Signer B, or a separate Worker?
- Do A and B live in separate Cloudflare accounts for production?
- Are same-account Service Bindings acceptable for local/dev only?
- What is the exact public transcript format?
- Which values must be committed publicly so the client can detect bad output?
- Does the first implementation require stronger verifying-share binding, or is
  Level C joined-state exclusion sufficient for the initial release?

## Non-Goals

- Full malicious-secure MPC proof system in the first implementation.
- Two-server online signing for every normal signature.
- Router-mediated plaintext A/B coordination.
- Compatibility with legacy joined-state server ceremonies beyond explicit
  persistence/request migration boundaries.

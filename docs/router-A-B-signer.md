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

- [ ] Define role-specific Router, A, B, client-output, and relayer-output
  types.
- [ ] Define encrypted envelope framing with transcript-bound associated data.
- [ ] Define signer identities and key rotation rules.
- [ ] Add type fixtures rejecting invalid branch combinations.
- [ ] Add source guards for forbidden imports in Router and signer code.

### Phase 2: Router Boundary

- [ ] Add the public split-derivation route.
- [ ] Parse and normalize public request metadata once.
- [ ] Verify auth, project policy, quota, abuse controls, expiry, and replay
  window.
- [ ] Forward A/B encrypted envelopes without decrypting them.
- [ ] Persist only public lifecycle state and payload hashes.
- [ ] Aggregate encrypted client packages into one response.

### Phase 3: Signer A/B Services

- [ ] Add private A and B signer endpoints.
- [ ] Decrypt only role-specific envelopes.
- [ ] Verify transcript binding and signer role.
- [ ] Load only signer-local root material.
- [ ] Reject any payload that contains joined state or the wrong role.
- [ ] Add direct A/B mutual authentication.

### Phase 4: Direct A/B Protocol

- [ ] Choose the two-party HSS/MPC primitive for split derivation.
- [ ] Implement A/B protocol message types with transcript-bound signatures.
- [ ] Ensure messages carry only protocol-safe material.
- [ ] Produce A/B shares of client and relayer outputs.
- [ ] Keep A/B round trips within the target budget.

### Phase 5: Output Delivery

- [ ] Encrypt A and B client-output packages directly to the client ephemeral
  key.
- [ ] Deliver relayer-output packages only to the designated relayer.
- [ ] Add client-side verification for matching transcript and output kind.
- [ ] Add relayer-side verification for matching transcript and output kind.
- [ ] Add downgrade rejection for clients requiring split derivation.

### Phase 6: Normal Signing Integration

- [ ] Store or activate `x_relayer_base` only in the designated relayer state.
- [ ] Keep normal signing on the Router plus active relayer path.
- [ ] Ensure normal signing routes cannot invoke A/B derivation paths
  accidentally.
- [ ] Add operational controls for relayer-share refresh.

### Phase 7: Validation And Benchmarks

- [ ] Add tests for Router opacity.
- [ ] Add tests for wrong-role signer payload rejection.
- [ ] Add tests for transcript mismatch, replay, expiry, and wrong relayer.
- [ ] Add tests proving no joined state crosses production route boundaries.
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

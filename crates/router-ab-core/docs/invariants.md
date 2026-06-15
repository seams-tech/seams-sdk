# Router A/B Protocol Invariants

This document records the initial verification-oriented invariants for
`router-ab-core::protocol`. The Rust code enforces these with constructors,
branch-specific enums, canonical encoders, vectors, and source guards. Future
Verus models should mirror these predicates over simplified abstract types.

## Role Separation

Invariant: a role-encrypted signer envelope is addressed only to `SignerA` or
`SignerB`.

Current Rust boundary:

- `RoleEncryptedEnvelopeV1::new` rejects Router, Client, and Server roles.
- `SignerIdentityV1::new` rejects Router, Client, and Server roles.
- `RoleEnvelopeAssignmentV1::new` requires signer role and envelope recipient
  role to match.
- `RouterToSignerPayloadV1::deriver_a` accepts only a Signer A assignment.
- `RouterToSignerPayloadV1::deriver_b` accepts only a Signer B assignment.

Verus target:

```text
valid_assignment(a) ==> a.signer.role == a.envelope.recipient_role
router_to_a(p) ==> p.assignment.signer.role == SignerA
router_to_b(p) ==> p.assignment.signer.role == SignerB
```

## A/B Peer Direction

Invariant: direct A/B peer messages cross signer roles.

Current Rust boundary:

- `AbPeerMessagePayloadV1::new` accepts `(SignerA, SignerB)` and
  `(SignerB, SignerA)`.
- Same-role peer messages are rejected.

Verus target:

```text
valid_peer_message(m) ==> (
  (m.from.role == SignerA && m.to.role == SignerB) ||
  (m.from.role == SignerB && m.to.role == SignerA)
)
```

## Output Kind Separation

Invariant: client-output packages always represent `x_client_base` for Client,
and server-output packages always represent `x_server_base` for Server.

Current Rust boundary:

- `ClientOutputPackageV1::recipient_role()` always returns `Client`.
- `ClientOutputPackageV1::opened_share_kind()` always returns `XClientBase`.
- `ServerOutputPackageV1::recipient_role()` always returns `Server`.
- `ServerOutputPackageV1::opened_share_kind()` always returns
  `XServerBase`.
- `RecipientOutputPackageV1` preserves branch-specific recipient and output
  kind.

Verus target:

```text
client_output(p) ==> p.recipient_role == Client
client_output(p) ==> p.opened_share_kind == XClientBase
server_output(p) ==> p.recipient_role == Server
server_output(p) ==> p.opened_share_kind == XServerBase
```

## Transcript Binding

Invariant: payloads carrying output packages bind every output package to the
same transcript digest as the parent payload.

Current Rust boundary:

- `SignerResponsePayloadV1::new` requires the client-output transcript digest
  and server-output transcript digest to match the response transcript digest.
- `ServerActivationPayloadV1::new` requires the server-output transcript
  digest to match the activation transcript digest.
- `WireMessageV1` binds the transport message kind, transcript digest, and
  canonical payload bytes into a SHA-256 digest.
- `payload-vectors-v1.json` and `wire-vectors-v1.json` act as anti-drift
  examples for the canonical encoders.

Verus target:

```text
valid_signer_response(r) ==> r.client_output.transcript == r.transcript
valid_signer_response(r) ==> r.server_output.transcript == r.transcript
valid_server_activation(a) ==> a.server_output.transcript == a.transcript
wire_digest(m) == sha256(encode_wire_message(m))
```

## Signer Set Policy

Invariant: Router A/B v1 signer sets use the `all(2)` policy with distinct
Signer A and Signer B identities.

Current Rust boundary:

- `SignerSetV1::v1_all2` constructs only `SignerSetPolicyV1::All2`.
- `SignerSetV1::validate` requires `deriver_a.role == SignerA`.
- `SignerSetV1::validate` requires `deriver_b.role == SignerB`.
- `SignerSetV1::validate` rejects duplicate signer ids.

Verus target:

```text
valid_signer_set(s) ==> s.policy == All2
valid_signer_set(s) ==> s.deriver_a.role == SignerA
valid_signer_set(s) ==> s.deriver_b.role == SignerB
valid_signer_set(s) ==> s.deriver_a.id != s.deriver_b.id
```

## Host Boundary

Invariant: service engines are host-injected and transport-neutral.

Current Rust boundary:

- `DeriverAEngine` and `DeriverBEngine` wrap a host value supplied by the
  adapter and enforce role-specific threshold-PRF batch input.
- `SignerHost` composes clock, CSPRNG, signer key store, root-share store, peer
  transport, and audit sink traits.
- Source guards reject Cloudflare, filesystem, environment, network, system
  clock, random-global, and common HTTP framework imports inside
  `router-ab-core/src/protocol`.

Verus target:

```text
engine_state(e) contains no adapter-global state
engine_step(input, host_view) depends only on explicit input and host_view
```

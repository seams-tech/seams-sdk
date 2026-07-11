# Ed25519 Yao Export Delivery Lifecycle V1

Status: **Phase 1 construction-independent host semantics; no production
transport or selected-profile authority**

This document freezes the host-only transition from an evaluated export output
to Client release and exact-identity redelivery. The keywords **MUST**, **MUST
NOT**, and **REQUIRED** are normative.

## 1. Authority and scope

`semantic-artifact-lifecycle-v1.md` owns export package descriptors, package-set
identity, and receipt fields. `output-sharing-v1.md` owns the A/B seed-share
equation. `output-party-views-v1.md` owns recipient visibility after release.
This document owns authorization ordering, retained-output identity, delivery
uncertainty, Client release, and redelivery.

The model is construction-independent. It defines no ciphertext format, opener,
network frame, durable transaction, Cloudflare primitive, profile negotiation,
or P0-P3 security claim.

## 2. Closed states and transitions

The version-one state family is:

```text
evaluated export
  -> output_committed[authorization = unconsumed]
       -> delivery_uncertain[authorization = unconsumed]
            -> released[authorization = consumed]
       -> released[authorization = consumed]
            -> redelivered[released identity unchanged]
```

`output_committed` MUST retain, as one move-owned value, the validated export
request, authenticated registered state, exact package set, exact A/B output
shares produced by the same evaluation, and output-committed receipt.
Commitment MUST NOT consume export authorization.

`delivery_uncertain` MUST retain the same values. It MUST NOT resample shares,
reevaluate the circuit, invoke either Deriver, derive contributions, or replace
the package set. Release evidence naming another package-set digest MUST be
rejected while retaining the pending state for a coherent retry.

`released` MUST consume the retained request and make it unavailable as callable
authorization. It MUST bind Client-delivery evidence and authorization-
consumption evidence to the exact output commitment. The authenticated
registered state and active state version remain unchanged.

`redelivered` is an exact released-state self-loop. The released receipt digest
and Client seed MUST remain identical.

## 3. Exact output provenance

The Client seed view MUST be constructed only by consuming `released`. The
builder extracts the exact A/B shares retained from the committed evaluation and
reconstructs `d` internally. Callers cannot supply an independent package set,
receipt, share pair, or seed.

The reconstructed seed MUST satisfy:

```text
d = d_A + d_B mod 2^256
A_pub = Ed25519PublicKey(d)
```

The second equality is checked against the registered public key bound by the
released artifacts. A distinct share pair reconstructing the same seed is
outside the accepted state transition because it lacks the retained evaluation
identity.

## 4. Receipt encodings

`LP32(x)` is `BE32(len(x)) || x`. Both receipt digests are:

```text
SHA-256(LP32(digest_domain) || LP32(receipt_encoding))
```

The output-committed receipt contains exactly 16 LP32 fields:

```text
LP32("seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed/v1")
LP32(0x01)                         # receipt kind
LP32(0x01)                         # output-committed status
LP32(0x05)                         # export request kind
LP32(public_request_context_digest[32])
LP32(authorization_digest[32])
LP32(transcript_digest[32])
LP32(transport_binding_digest[32])
LP32(artifact_suite_digest[32])
LP32(one_use_execution_id[32])
LP32(input_provenance_pair_digest[32])
LP32(host_reference_evaluation_evidence_digest[32])
LP32(export_package_set_digest[32])
LP32(registered_A_pub[32])
LP32(deriver_a_output_commitment_evidence_digest[32])
LP32(deriver_b_output_commitment_evidence_digest[32])
```

Its digest domain is
`seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed-digest/v1`.

The released receipt contains exactly 17 LP32 fields:

```text
LP32("seams/router-ab/ed25519-yao/semantic-receipt/export-released/v1")
LP32(0x02)                         # receipt kind
LP32(0x02)                         # released status
LP32(0x05)                         # export request kind
LP32(public_request_context_digest[32])
LP32(authorization_digest[32])
LP32(transcript_digest[32])
LP32(transport_binding_digest[32])
LP32(artifact_suite_digest[32])
LP32(one_use_execution_id[32])
LP32(input_provenance_pair_digest[32])
LP32(host_reference_evaluation_evidence_digest[32])
LP32(export_package_set_digest[32])
LP32(registered_A_pub[32])
LP32(output_committed_receipt_digest[32])
LP32(client_delivery_evidence_digest[32])
LP32(consumed_authorization_evidence_digest[32])
```

Its digest domain is
`seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1`.
Every typed digest field is exactly 32 bytes and nonzero.

## 5. Zero private-evaluation work

Delivery uncertainty, first release, and redelivery each carry five zero
counters:

```text
yao_evaluations
deriver_a_invocations
deriver_b_invocations
contribution_derivations
output_share_samples
```

These counters cover host-reference private evaluation only. They exclude
ciphertext opening, decryption, authentication, storage, network I/O, retries,
and recipient acknowledgement.

## 6. Canonical evidence corpus

The exact envelope is:

```text
schema         = seams:router-ab:ed25519-yao:export-delivery-vectors:v1
protocol_id    = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_export_delivery_v1
```

`vectors/ed25519-yao-export-delivery-v1.json` contains exactly one case,
`export_output_commit_release_redelivery_v1`, in this order:

1. `output_committed`;
2. `delivery_uncertain`;
3. `released`;
4. `redelivered`.

An independent verifier MUST enforce exact object order and shape, parse both
LP32 receipts, recompute both receipt digests, validate every cross-link, require
the authorization-state order, preserve package and state identities, derive the
registered key from the released seed, enforce every zero counter, and reject
unknown or secret-control fields.

## 7. Digest and delivery limits

Digest equality proves equality of the committed semantic encodings under the
model's SHA-256 assumption. It makes no claim that two randomized ciphertext
byte strings are equal. Client-delivery evidence is an opaque, nonzero host slot.
It does not prove production delivery, authenticated opening, durable replay
consumption, or recipient acknowledgement.

## 8. Remaining production blockers

Phase 6B still owns selected-profile frames, authenticated transport, recipient
encryption and opening, durable coordination where required, corruption-game
claims, and deployed replay enforcement. Activation delivery to Client and
SigningWorker is owned by the separate activation-delivery and activation-
recipient companions.

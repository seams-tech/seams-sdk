# Activation Recipient Delivery Lifecycle V1

Status: host-only construction-independent transition evidence. This document
defines no production ciphertext opener, network frame, durable transaction,
fair delivery, or P0-P3 security claim.

## Authorization ordering

The lifecycle encodes one monotonic activation-authorization timeline through
move-only types:

1. `PendingActivationPreStateV1`: activation authorization is not issued.
2. `ActivationRequestV1`: activation control is admitted and authorization is
   unconsumed.
3. `ActivationMetadataConsumptionSuccessV1`: authorization is consumed.
4. Delivery uncertainty, recipient release, redelivery, and SigningWorker
   activation retain the consumed state. Release never consumes authorization
   a second time.

## Exact output ownership

Metadata consumption retains the output-committed package set and the exact
four A/B scalar shares from the same registration, recovery, or refresh
evaluation. Recipient-release evidence binds:

- the activation package-set digest;
- the preceding output-committed receipt digest;
- the activation-control transcript digest;
- a purpose-typed Client delivery evidence digest; and
- a purpose-typed SigningWorker delivery evidence digest.

All evidence digests are opaque host-reference slots. Their presence records a
required boundary; it does not prove that a production transport or opener
exists.

## Atomic recipient release

One successful release consumes the metadata-consumed value and yields two
disjoint move-only capabilities:

- `HostOnlyActivationClientReleasedV1`, containing only the reconstructed
  Client scalar and its release binding; and
- `HostOnlySigningWorkerActivationReleaseAuthorityV1`, retaining the complete
  origin-specific metadata state required for worker activation.

Release reconstructs the Client scalar from the exact retained A/B Client
shares. SigningWorker preparation accepts only the worker release authority.
It constant-time compares both authenticated opened worker shares with the
exact retained same-evaluation shares before the retained shares can be
destroyed, then performs the existing descriptor, recipient, epoch, point,
joined-output, and registered-key checks.

A rejected release returns the exact delivery-pending state. A rejected worker
preparation returns the exact worker release authority. Neither failure creates
a raw-metadata activation path.

## Uncertainty and redelivery

`delivery_uncertain_v1` preserves the metadata-consumed output, authorization
state, package-set digest, receipt digest, and activation transcript. A
coherent retry performs zero private reevaluation. Host-only redelivery is an
exact released-state identity self-loop with all five private-work counters at
zero.

## Current evidence and open work

Two focused Rust tests cover all three activation origins, exact Client scalar
release, disjoint capability creation, uncertainty, cross-output rejection,
retry, redelivery, identity retention, and zero reevaluation. The existing ten
SigningWorker activation tests now obtain their authority only through this
release transition and check exact retained worker shares.

The committed strict three-origin JSON corpus cross-links the canonical
semantic-lifecycle and output-party-view corpora. Four focused Rust corpus
tests and five independent Python mutation tests enforce authorization
monotonicity, exact output identity, capability separation, release-only Client
scalar custody, uncertainty/redelivery identity, zero private work, and
recursive secret exclusion. Ten Lean structural theorems freeze the same host
authorization, custody, identity, and zero-work relations.

Production opener, transport acknowledgements, durable replay, complete runtime
party views, and selected-profile evidence remain open. The corpus and Lean
model do not expand this document's host-only claim.

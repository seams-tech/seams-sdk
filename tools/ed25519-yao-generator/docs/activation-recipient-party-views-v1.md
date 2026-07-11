# Ed25519 Yao Activation Recipient Party Views V1

Status: host-only construction-independent recipient-custody specification. It
defines no production ciphertext opener, transport frame, durable transaction,
noninterference theorem, or P0-P3 security claim.

## 1. Authority and separation

`output-party-views-v1.md` retains its exact five-stage output-view family. Its
activation Client and SigningWorker extensions remain empty before recipient
release. This companion starts only after the activation-delivery lifecycle has
consumed authorization and produced the atomic two-recipient release.

`activation-delivery-lifecycle-v1.md` owns authorization ordering, exact output
identity, uncertainty, atomic release, and redelivery. `signing-worker-
activation-v1.md` owns authenticated opened-share validation, activated scalar
custody, and strict receipt verification. This document owns the host-only role
projections of those transitions.

## 2. Closed stages

Exactly two stages are modeled:

| Stage | Required input | Meaning |
| --- | --- | --- |
| `recipients_released` | `HostOnlyActivationRecipientsReleasedV1` | Client scalar capability and opaque SigningWorker release authority exist atomically |
| `signing_worker_activated` | retained Client capability plus `SigningWorkerActivationSuccessV1` | the Client capability remains released and the SigningWorker owns one receipt-verified activated state |

There is no optional stage, runtime security-profile selector, generic payload,
frame list, retry bag, or durable-record field.

## 3. Common public view

Every role projection for one stage carries one equal common public value.

`recipients_released` contains exactly:

- origin kind: registration, recovery, or refresh;
- activation package-set digest;
- output-committed receipt digest;
- activation-control transcript digest;
- the consumed authorization state;
- terminal stage `recipients_released`; and
- the five zero-valued private-work counters.

`signing_worker_activated` contains exactly:

- origin kind;
- activation package-set digest;
- output-committed receipt digest;
- activation epoch;
- SigningWorker identity and recipient-key epoch;
- registered Ed25519 public key and public `X_server` point;
- opaque nonzero output-storage evidence digest;
- verified SigningWorker activation-receipt body encoding, digest, signature,
  receipt-key epoch, receipt-key digest, and verifying key;
- the consumed authorization state; and
- terminal stage `signing_worker_activated`.

The storage-evidence digest is an opaque host reference. Its presence proves no
database write, durability, rollback protection, or acknowledgement.

## 4. Closed role extensions

| Role | `recipients_released` | `signing_worker_activated` |
| --- | --- | --- |
| Deriver A | empty | empty |
| Deriver B | empty | empty |
| Client | Client scalar capability: `x_client_base`, package-set digest, Client delivery-evidence digest | the exact same Client capability |
| SigningWorker | opaque release-authority projection: package-set digest and SigningWorker delivery-evidence digest | sealed receipt-verified activated state; the Rust view exposes public bindings and consumes the state without exposing its scalar |
| Router | empty | empty |
| Observer | empty | empty |
| Diagnostics/logs | empty | empty |

The Client and SigningWorker extensions are different types. No role projection
contains both extensions. Deriver and infrastructure roles receive no copied
recipient output.

The host-only evidence DTO may include `x_server_base_hex` only inside the
SigningWorker extension of `signing_worker_activated`. The independent verifier
reconstructs it from the already committed synthetic A/B SigningWorker shares,
checks its point against `X_server`, and checks the registered-key relation.
The Rust activated-state API gains no scalar accessor.

## 5. Move-only projection rules

The core Rust model uses two private validated aggregates. Each aggregate owns
the common public value and the disjoint recipient capabilities or activated
state. It implements neither `Clone`, `Copy`, nor Serde.

Static consuming projection methods exist for exactly seven roles. Observing
one role consumes the aggregate and drops every unselected private extension.
A test requiring another role rebuilds a canonical synthetic fixture.

The activated-stage builder requires the retained Client capability and one
strictly verified SigningWorker activation success. It rejects:

- different package-set identities;
- different output-committed receipt identities;
- different lifecycle origins;
- a registered-key or `X_server` relation mismatch;
- a Client scalar that does not match the committed `X_client`; or
- a worker receipt/body/digest/signature inconsistency.

The activation success retains the exact trusted receipt authority used during
strict verification. The activated common view and evidence DTO derive its key
epoch, key digest, and verifying-key bytes from that retained authority.

No builder accepts raw metadata, raw A/B shares, an unsigned activated state, a
receipt-pending state, or a generic role selector.

## 6. Strict evidence corpus

The canonical corpus schema is:

```text
seams:router-ab:ed25519-yao:activation-recipient-party-views:v1
```

Its evidence scope is:

```text
host_only_synthetic_activation_recipient_party_views_v1
```

It contains exactly three ordered cases:

1. registration-origin activation;
2. recovery-origin activation;
3. refresh-origin activation.

Each case contains both closed stages and all seven exact role extensions. It
cross-links the ceremony-context, provenance, semantic-lifecycle, output-party-
view, activation-delivery, and SigningWorker activation reference values.

The corpus contains synthetic role-private values solely for independent host
verification. Exact shapes and recursive boundary checks reject roots,
contributions, joined seed, A/B share fields outside their existing companion,
ciphertexts, decryption keys, opener state, OT state, garbled tables, labels,
masks, protocol frames, raw durable records, and generic payloads.

## 7. Required executable checks

Rust and an independent implementation must:

- require exact LF-terminated canonical bytes, schema, scope, case order, stage
  order, field order, and role set;
- cross-link all public identities to the required companion corpora;
- prove every pre-release Client and SigningWorker output view remains empty;
- require consumed authorization and zero private work at release;
- require one Client scalar capability and one opaque SigningWorker authority at
  release, with every other extension empty;
- retain the exact Client capability through worker activation;
- verify the worker receipt body, digest, strict Ed25519 signature, worker/key
  binding, package and output-receipt binding, storage-evidence binding,
  `X_server`, and registered public key;
- require the receipt epoch and verifying key to equal the independently pinned
  synthetic authority for that canonical origin, so a coherently re-signed
  substituted authority is rejected;
- reconstruct the synthetic activated SigningWorker scalar only inside the
  independent evidence checker;
- reject recipient swaps, joined-output duplication, cross-origin splicing,
  authority substitution, receipt mutation, forbidden fields, and any frame or
  durable-record addition.

The Lean model freezes the closed stage/role tables, pre-release emptiness,
disjoint recipient custody, same-output identity, Client-capability retention,
sealed worker activation, and infrastructure emptiness. These structural
theorems make no protocol-privacy or delivery claim.

## 8. Explicit exclusions

This companion supplies no evidence for:

- production package opening or recipient encryption;
- sent or received protocol frames;
- authenticated network delivery or acknowledgement;
- replay admission, retry persistence, crash recovery, or database atomicity;
- scalar erasure after every runtime failure;
- real/ideal simulation, noninterference, selective-failure resistance, or
  adaptive corruption;
- Client and SigningWorker non-collusion; or
- any P0, P1, P2, or P3 security claim.

Profile-specific frame graphs remain blocked until Phase 6A selects one coherent
profile and Phase 6B freezes its exact bytes. Durable transition evidence
remains Phase 6B-7 work.

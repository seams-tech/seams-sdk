# Invariants And Behaviors

This document is the pre-implementation checklist for the split-derivation
primitive. Candidate code should not advance until these items are either
specified or explicitly deferred.

## State Invariants

### Forbidden Joined State

No single server-side role may materialize:

- joined `d`
- joined `a`
- joined `x_client_base`

The client may not materialize:

- joined `d`
- joined `a`
- joined `y_relayer`
- joined `tau_relayer`

Router may not materialize:

- plaintext A and B derivation shares for the same ceremony
- decrypted client delivery material
- decrypted SigningWorker delivery material

### Allowed Openings

Allowed openings are:

- client opens `x_client_base`
- active SigningWorker opens `x_relayer_base`

All other openings are invalid.

### Role Separation

A and B must have different role identities, different persistent role state,
and different envelope decryption keys. The protocol must reject swapped or
duplicated deriver identities.

### Epoch Separation

Root-share epoch is part of the derivation context. Material from one epoch
must not verify under another epoch.

### Recipient Separation

Client-output material and SigningWorker-output material must use distinct
domain separation labels and recipient identities. A package encrypted for one
recipient must not be valid for another recipient.

## Context Invariants

The context encoding must include, in fixed order:

1. context version
2. candidate id
3. request kind
4. correctness level
5. network id
6. account id
7. account public key
8. root-share epoch
9. ceremony id

Every field is required. Empty identity, account, epoch, or ceremony fields are
invalid.

## Transcript Invariants

The transcript binding must include:

- encoded context bytes
- Router identity
- Deriver A identity
- Deriver B identity
- SigningWorker identity
- client identity

Changing any bound field must change the transcript digest.

## Behavioral Requirements

### Boundary Parsing

Raw requests, JSON fixtures, Worker payloads, and storage records are parsed at
the boundary into typed internal values. Core derivation functions must not
accept partial request objects or raw unvalidated strings for identity,
account, epoch, or ceremony state.

### Replay

The same `ceremony_id` cannot be accepted for different account scope, root
epoch, role identity, recipient, or request kind.

### Idempotency

A repeated request with the exact same transcript can return the same public
evidence or encrypted delivery package. A repeated request with changed bound
fields must fail.

### Diagnostics

Diagnostics may include:

- role label
- candidate id
- request kind
- root epoch label
- ceremony id
- stable error code

Diagnostics must not include:

- secret shares
- joined material
- decrypted delivery material
- private keys
- raw encrypted envelope plaintext

### Source Guards

Before production use, source guards must fail on new code that constructs or
logs forbidden joined-state names outside documentation and explicit test
fixtures.

## Candidate A: MPC Threshold PRF Behavior

Required before implementation:

- define A/B partial format
- define partial verification proof
- define combiner role
- define recipient delivery format
- define refresh behavior
- prove or test that one partial is insufficient to reconstruct forbidden
  joined state
- measure coordination round trips

Risk to resolve:

- if Router combines plaintext partials, Router may become a stronger trust
  point unless the partials are designed as public verification material or
  encrypted recipient delivery material.

## Candidate B: Split Root Derivation Behavior

Required before implementation:

- define A/B root material
- define root-share refresh
- define output-share derivation labels
- define output delivery format
- define recipient verification behavior
- prove or test that one root share is insufficient to reconstruct forbidden
  joined state
- measure coordination round trips

Risk to resolve:

- if one deriver can bias output silently, Minimum Level C may need extra
  transcript evidence or public-share binding earlier than planned.

## Formal Verification Requirements

The proof plan must cover:

- context field inclusion
- context field order
- transcript field inclusion
- role/output authorization
- forbidden joined-state exclusion for single role views
- epoch separation
- recipient separation
- state-machine transition safety
- vector anti-drift against production Rust helpers

The proof plan may defer:

- computational PRF security
- elliptic-curve hardness assumptions
- envelope encryption security
- deployment integrity

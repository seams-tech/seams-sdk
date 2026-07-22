# Ed25519 Yao Uniform Abort Envelope V1

Status: **normative construction-independent host-reference contract**

This document freezes the public shape shared by rejected registration,
activation, recovery, refresh, and export attempts. It does not freeze a
production wire encoding, failure timing, profile-specific failure registry,
or selective-failure claim.

## 1. Authority and scope

`ideal-functionalities-v1.md` Section 10 owns the uniform abort requirement.
This companion freezes the exact host model, canonical synthetic corpus, and
its ceremony linkage. `router-ab/ed25519-yao/implementation-plan.md` Phase 6A selects the P0-P3 claim and Phase
6B freezes the production failure points, frame graph, encoding, and any timing
equivalence required by that claim.

The host evidence establishes only:

- one closed envelope shape for all five request kinds;
- the request kind copied from a validated ceremony DAG;
- the public transcript digest copied from that DAG;
- one redacted host-reference failure code;
- one terminal `aborted` state; and
- exclusion of private values, peer blame, and request-context details.

## 2. Exact host type

The construction-independent type is:

```text
UniformLifecycleAbortV1 {
  request_kind
  public_transcript_digest
  public_failure_code
  terminal
}
```

The only host-reference values are:

```text
public_failure_code = rejected
terminal = aborted
```

The constructor accepts a sealed `CeremonyValidatedDagV1`. Callers cannot
supply the request kind or transcript digest independently. The type has no
Serde implementation and its fields are private.

The envelope has no request-context digest. A request-context digest remains
public elsewhere in the ceremony, but including it here would violate the
exact four-field abort result shape and create an unnecessary failure-surface
distinction.

## 3. Forbidden fields and values

The envelope MUST NOT contain:

- an authorization digest or authorization detail;
- a request-context digest;
- a Deriver role, suspected party, blame label, or peer identity;
- a peer frame, payload, package plaintext, contribution, output share, joined
  value, seed, scalar, label, mask, OT value, garbling state, or private key;
- a retry token, retry delay, ticket state, or nonterminal result; or
- a branch-specific error detail.

Logs and public views may copy the exact envelope. They may not enrich it with
protected diagnostics.

## 4. Canonical evidence corpus

The committed file is:

```text
vectors/ed25519-yao-uniform-abort-envelope-v1.json
```

Its schema and evidence scope are:

```text
schema = seams:router-ab:ed25519-yao:uniform-abort-envelope-vectors:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_uniform_abort_envelope_v1
```

The top-level key order is:

```text
schema
protocol_id
evidence_scope
cases
```

The case order is registration, activation, recovery, refresh, export. Every
case has exact key order:

```text
request_kind
source_ceremony_case_id
envelope
```

The source ceremony identifiers are respectively:

```text
ceremony-registration-v1
ceremony-activation-v1
ceremony-recovery-v1
ceremony-refresh-v1
ceremony-export-v1
```

Every `envelope` has exact key order:

```text
request_kind
public_transcript_digest_hex
public_failure_code
terminal
```

The request kind equals its enclosing case. The transcript digest equals the
independently reconstructed digest from the named ceremony-context case. The
failure code is `rejected` and the terminal state is `aborted`.

The corpus is pretty JSON with LF line endings and exactly one trailing LF.
Unknown, missing, reordered, duplicate, or optional fields are rejected.

## 5. Required evidence

Rust and an independent verifier MUST:

- enforce the exact schema, field order, case order, and canonical bytes;
- independently verify the ceremony-context corpus;
- cross-link every transcript digest to its named ceremony case;
- reject request-kind or source-case splicing;
- reject any other failure code or terminal state; and
- reject every private, blame-bearing, request-context, or branch-specific
  field added to an envelope.

Compile-time or source-surface evidence MUST show that fields are private, the
envelope has no authorization, request-context, role, or package accessor, and
the host type is not a production wire DTO.

Every admitted registration, recovery, refresh, or export host-reference
evaluation failure MUST expose this envelope. Its detailed semantic cause may
remain available to crate-owned audit handling, but MUST be inaccessible to
external callers and absent from `Debug` output. Activation metadata rejection
MUST use the same envelope.

## 6. Explicit nonclaims

This contract supplies no evidence for:

- equality of success and failure timing;
- independence of failure behavior from protected inputs;
- selective-failure resistance;
- identification or handling of a malicious Deriver;
- authenticated transport, frame parsing, timeout, disconnect, or replay
  behavior;
- ticket destruction, erasure, retry, redelivery, or durable persistence;
- production error-code bytes or compatibility; or
- P0, P1, P2, or P3 correctness-with-abort or protocol security.

Those claims remain blocked until the selected profile, frame graph, state
machine, and adversary games are frozen and reviewed.

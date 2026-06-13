# Spec Review

This review records what is still missing before implementation should proceed.
The current specs are directionally correct, but they are not yet detailed
enough to implement either candidate safely.

## Review Verdict

Do not begin candidate implementation yet.

The crate can continue with typed scaffolding, vector-shape work, and proof
model scaffolding. Candidate code should wait until the P0 and P1 gaps below
are resolved.

Current status:

- threat model, encoding, envelope delivery, Minimum Level C, and
  candidate-specific spec files now exist
- state-machine ownership, refresh context, error contracts, secret
  classification, vector matrix, public-share-binding, and API shape now exist
- candidate implementation remains blocked by unresolved candidate formulas,
  proof choices, authentication choices, refresh semantics, and product
  acceptance of the threat-claim matrix

## P0 Blockers

### Threat Model And Trust Claims

Status: initial spec added in [threat-model.md](threat-model.md).

Missing details:

- confirm product acceptance that A+B collusion breaks the server-blind claim
- confirm product acceptance that Router plus one deriver should preserve
  server blindness
- decide whether public-share-binding hardening is required before production
  for malicious deriver detection

Required output:

- final sign-off on threat-claim matrix
- list of claims deferred to public-share-binding hardening

### Field-Level Transcript And Context Spec

Status: initial spec added in
[encoding-and-transcript.md](encoding-and-transcript.md).

Missing details:

- confirm role identity string format
- decide whether account public key validation belongs in this crate or only at
  adapters
- add candidate-specific derivation labels after candidate formulas settle

Required output:

- committed vectors for every transcript-bound field

### Envelope And Delivery Boundary

Status: initial spec added in [envelopes-and-delivery.md](envelopes-and-delivery.md).

Missing details:

- choose adapter authentication mode: sender-authenticated encryption, detached
  role signature, or mTLS plus signed receipt
- define exact plaintext schemas for each content kind
- decide recipient public-key identity format

Required output:

- Rust structs and vectors for envelope headers, AAD, and package commitments

### Minimum Level C Verification Spec

Status: initial spec added in [minimum-level-c.md](minimum-level-c.md).

Missing details:

- choose exact Rust evidence structs
- add accepted and rejected evidence vectors
- add error enum variants listed in the spec
- define address verification evidence shape

Required output:

- `verify_minimum_level_c_v1` API and vector corpus

### Candidate Algorithm Specs

Status: initial specs added in
[candidate-mpc-threshold-prf.md](candidate-mpc-threshold-prf.md) and
[candidate-split-root.md](candidate-split-root.md).

Missing details for `mpc_threshold_prf_v1`:

- proof format
- refresh formula
- share commitment format
- final relation to `threshold-prf`
- whether proof verification is part of Minimum Level C

Missing details for `split_root_derivation_v1`:

- refresh formula
- final `HashToScalar` suite
- bias-resistance mechanism
- whether preserving refresh is possible
- whether public-share-binding is mandatory for this candidate

Required output:

- algebraic formulas
- secret/public classification for every field
- candidate-specific leakage tables
- test vectors for each request kind

## P1 Required Before Prototype

### State Machine Ownership

Status: initial spec added in [state-machine.md](state-machine.md).

Required details:

- confirm retention period for replay records
- confirm whether concurrent active ceremonies are allowed per account in the
  product API

### Refresh Context Extension

Status: initial spec added in [refresh-context.md](refresh-context.md).

Required details:

- resolve candidate-specific preserving refresh
- decide whether split-root refresh creates a new verified epoch relation

### Error And Diagnostics Contract

Status: initial spec added in
[errors-and-diagnostics.md](errors-and-diagnostics.md).

Required details:

- implement enum and diagnostics structs
- add source guards and redaction vectors

### Secret/Public Classification

Status: initial spec added in [secret-classification.md](secret-classification.md).

Required details:

- apply the classification to every Rust struct as it lands
- run constant-time review on secret arithmetic and comparisons

### Vector Matrix

Status: initial spec added in [vector-matrix.md](vector-matrix.md).

Required details:

- generate and commit vectors after Rust helpers exist

## P2 Useful Before Candidate Selection

### Benchmark Protocol

Current benchmark requirements need more deployment detail.

Required details:

- native benchmark command
- wasm benchmark command
- Workers bundle measurement command
- cold-start measurement method
- payload-size measurement
- p50, p95, p99 reporting
- target thresholds for embedded clients and Workers

### Formal Verification Scope Boundary

The FV docs list proof targets. They need an assumption registry.

Required details:

- assumptions represented as axioms or uninterpreted functions
- computational assumptions outside proof
- anti-drift tests tied to committed vectors
- proof obligations per release gate
- what must be proven before public-share-binding hardening

### API Shape

Status: initial spec added in [api-shape.md](api-shape.md).

Required details:

- implement typed APIs behind the current placeholder candidate gates

## Recommended New Spec Sections

Added sections:

- `threat-model.md`
- `encoding-and-transcript.md`
- `envelopes-and-delivery.md`
- `minimum-level-c.md`
- `candidate-mpc-threshold-prf.md`
- `candidate-split-root.md`
- `state-machine.md`
- `errors-and-diagnostics.md`
- `secret-classification.md`
- `vector-matrix.md`
- `api-shape.md`
- `public-share-binding.md`

Remaining spec decisions can be tracked inside these files.

## Implementation Decision

Proceed next with implementation scaffolding in this order:

1. implement current typed errors and redacted diagnostics
2. implement context/transcript digest helpers from the encoding spec
3. add request-scope enum with refresh old/new epoch support
4. implement envelope header, AAD, package commitment, and idempotency helpers
5. implement Minimum Level C typed evidence verification
6. generate context, transcript, envelope, and evidence vectors
7. add source guards for diagnostics and forbidden joined-state exposure

Candidate prototype code should start after the proof/authentication/refresh
open decisions are resolved.

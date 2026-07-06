# Covert-Security Spot-Check Transcript Design Note

Status: design note only. Do not implement without cryptographic review,
formal-model updates, and an explicit product decision accepting covert
security for this HSS flow.

Date: July 6, 2026

## Decision Context

The current Ed25519 HSS registration path preserves standard Ed25519 seed
export. That closes the simpler protocol escapes:

- normal signing base shares must correspond to
  `clamp(SHA-512(seed)[0..32])`;
- replacing the critical path with MPC-native scalar shares breaks standard
  seed export for the same public key;
- lazy export only defers seed opening and keypair derivation, which is a small
  tail win;
- eager pre-auth derivation creates DDoS pressure and is blocked when client
  inputs depend on auth-derived recovery material.

The remaining protocol-level latency lever is reducing the transcript work
required to enforce malicious-security style correctness. Today's retained
backend pays for broad per-gate/per-bit commitments and provenance. The E0
profile shows the expensive domains are exactly those commitment/provenance
families.

## Proposed Question

Can we replace part of the per-gate committed transcript with a covert-security
or probabilistic-verification transcript that detects cheating with a quantified
probability, while preserving:

- the same seed-to-scalar-to-public-key derivation;
- the same public key and standard export semantics;
- no joined secret values in normal registration, signing, restore, or export;
- constant-time execution with no secret-dependent branches, indexes, widths,
  or allocation sizes;
- durable replay resistance and backend-version separation.

This is a security-model change. It is not a drop-in optimization.

## Security Model Change

Current target: malicious-security style local verification, where every
materialized commitment/provenance item is available for deterministic
verification at the relevant boundary.

Candidate target: covert security. A cheating party can deviate, but the
transcript catches and attributes cheating with probability at least `p`.

The product must choose an acceptable detection probability before code. A
useful design note must state the detection bound in terms of concrete
parameters: circuit size `N`, checked relations, challenge size, challenge
domain, and adversary-visible messages before challenge derivation.

## Simple Sampling Caveat

Naive random gate sampling is probably too weak.

If changing one unchecked gate can bias the final scalar or public key, then
sampling `s` gates out of `N` detects a one-gate cheat with probability roughly
`s / N`. For large SHA-512 hidden-eval circuits, this is not a meaningful
deterrent unless `s` becomes large enough to erase the performance win.

Therefore, the first proof obligation is negative as much as positive:

- either prove that any output-changing cheat affects a large checked set;
- or reject simple sampling and use a stronger batch-verification shape.

### Trial 1: Naive Sampling

Decision: reject.

The current physical-counter baseline shows `192,900` derived-commitment
hashes for the retained hidden-eval path, with `126,692` of those in
`eval_xor_local_word`. Even if a simple sampler checked `2,048` positions, a
single-position deviation in that dominant family would be detected with
probability about `1.6%`. Raising the sample count enough to make that
probability product-credible would keep too much of the commitment work on the
hot path.

Simple spot sampling can still be useful as an audit layer on top of a stronger
aggregate proof, but it is not a candidate replacement for per-gate/per-bit
transcript binding.

### Trial 2: Random Linear Toy Batch Check

Decision: keep as proof-shape scaffold only.

The toy test suite models a public residual vector over a small field and checks
that:

- zero residuals pass;
- a single nonzero residual fails when coefficients are derived after the
  transcript roots are fixed;
- challenge coefficients bind backend version, operation purpose, context
  binding, transcript roots, and output commitment;
- adaptive residuals chosen after seeing the challenge can cancel the random
  linear check.

The last fixture is the important constraint. A random linear check is not a
standalone proof. It only becomes meaningful when the relation vectors are
committed by roots before the Fiat-Shamir challenge is derived. Any real
candidate must define the committed relation family first, then prove that the
opening/batch-check protocol prevents post-challenge residual selection.

## Candidate Shapes

### A: Batch Random Linear Checks

Replace many per-gate commitments with compact roots plus randomized linear
consistency checks over whole vectors of relation claims.

Possible target families:

- Boolean-to-arithmetic and arithmetic-to-Boolean conversions;
- multiplication material consistency;
- derived commitment families currently dominated by `eval_xor_local_word`;
- output-projection relation checks.

Challenge rule:

- both parties commit to compact transcript roots first;
- derive challenges with domain separation from context binding, backend
  version, candidate digest, transcript roots, output commitments, and operation
  purpose;
- use only public challenge values and public loop bounds.

Required proof:

- a nonzero relation error is detected with probability at least
  `1 - 2^-k` or with an explicitly accepted weaker covert bound;
- no relation check requires reconstructing a joined secret;
- the challenge cannot be biased after seeing sampled positions or coefficients.

First prototype target:

- multiplication-material consistency or A2B/B2A consistency, because those
  relation families have explicit algebraic constraints to batch;
- use a benchmark-only backend object named `covert_hss_backend_v1_experiment`,
  with no production parser accepting it;
- keep `eval_xor_local_word` as a measurement target, but do not start there
  unless the proof identifies a relation that checks correctness rather than
  merely compressing commitment storage.

The prototype should answer one narrow question: can one relation family replace
per-item commitments with roots plus a public Fiat-Shamir challenge, while
catching any nonzero residual with the claimed probability and without opening
joined secrets?

### B: Replicated Circuit Spot-Checks

Run multiple compact executions and open a random subset for audit. Keep one
unopened execution as the live output.

This is the classic cut-and-choose family. It may be easier to reason about,
but it likely increases CPU unless the compact unchecked execution is much
cheaper than the current committed one.

Required proof:

- opened executions reveal no secret material beyond approved shares;
- unopened execution is bound to the same context and output commitments;
- detection probability is quantified for the chosen number of replicas.

### C: Aggregate Roots With Probabilistic Openings

Keep per-stage or per-operation roots instead of per-bit commitments, then open
a challenge-selected subset of leaves plus batch checks for the rest.

This is closest to E4/E5. It can be treated as a covert-security variant of
aggregate-root work, rather than a full protocol replacement.

Required proof:

- exact root preimage and leaf derivation;
- challenge derivation binds root, context, backend, and output;
- opening policy catches any output-affecting inconsistency at the chosen
  covert-security level.

## Boundary Objects

Any experiment must introduce new backend-versioned objects. Do not reuse the
current malicious transcript formats.

Minimum new objects:

- `covert_hss_backend_v1` backend version;
- transcript-root record, bound to context binding and candidate digest;
- challenge record, bound to transcript roots and operation purpose;
- audit-opening record, containing only public openings and approved share-local
  material;
- verification result record with an explicit detection probability parameter.

Mixed current-backend and covert-backend objects must be rejected at every
request, persistence, and artifact boundary.

Current backend state:

- `DdhHssBackendVersion::CURRENT` is
  `ddh_hss_backend_v4_ch_gated_select_root`;
- current wire frames reject unknown backend versions;
- any covert experiment must add a separate parser path that is reachable only
  from benchmark or formal-model code until the product/security decision is
  made.

Do not add a runtime flag that causes current registration, unlock, restore, or
export flows to accept covert objects. The experiment boundary is a distinct
backend version, not a compatibility mode.

## Constant-Time Requirements

All challenge-selected checks must execute with public loop bounds and
publicly determined indexes.

Allowed:

- selecting public transcript positions after a public Fiat-Shamir challenge;
- fixed-width vector checks;
- fixed-size opening batches.

Forbidden:

- branching on secret shares, secret-derived carry values, scalar bytes, or
  hidden intermediate bits;
- allocation sizes depending on secret values;
- table indexes derived from secret values;
- early exits on failed secret-dependent checks;
- any shortcut that reconstructs `seed`, `a`, `x_client_base + x_server_base`,
  or another joined secret during normal registration/signing.

Before retention, run constant-time analysis on the touched Rust kernels for
`x86_64` and `arm64`, and manually review every flagged branch/division for
secret data flow.

## Experiment Plan

1. **Threat-model memo**
   State exactly what the product accepts: detection probability, attribution,
   user-visible remediation, and whether a detected cheat blocks wallet
   creation permanently or restarts under the malicious transcript.

2. **Counter audit**
   Map E0 physical counters to relation families. Identify which families can
   be batch-checked without reconstructing joined secrets.

3. **Toy proof**
   Build a small algebraic model for one family, preferably multiplication
   material or A2B/B2A consistency. Prove the batch check's soundness bound.

4. **Native prototype**
   Add a benchmark-only backend version for one relation family. It must not
   be product-reachable.

5. **Equivalence and rejection fixtures**
   Prove current and covert backend objects cannot mix. Prove stale/current
   backend parsers reject the new objects unless the explicit experiment flag is
   enabled.

6. **Formal verification**
   Extend the formal model before any product path uses the new transcript.

## Concrete Next Slice

The next implementation slice is intentionally small:

1. Add an explicit current-backend rejection fixture for
   `covert_hss_backend_v1_experiment`.
2. Add a benchmark-only toy module that models a vector relation
   `residual[i] = 0` over a public field, derives public Fiat-Shamir
   coefficients from committed roots, and verifies that a nonzero residual is
   rejected in the model.
3. Do not connect that module to the HSS runtime.
4. Run the formal verification suite only after the toy model becomes a
   protocol candidate touching real relation code.

This slice tests the boundary and proof shape. It does not claim a latency win.

Current trial artifacts:

- `crates/ed25519-hss/tests/covert_security_design/mod.rs` models the public
  batch-check shape over a toy field;
- `DdhHssBackendVersion` rejects `covert_hss_backend_v1_experiment` in the
  current backend parser.

## Retention Gates

Retain only if all are true:

- product accepts the covert-security model in writing;
- cryptographic review approves the soundness bound;
- detection probability is parameterized and visible in artifacts/diagnostics;
- the touched relation family moves both hidden-eval legs or removes enough
  commitment work to plausibly move `max(advance leg, artifact leg)`;
- `cargo hss-fv all` passes;
- boundary corruption and downgrade/mixing fixtures pass;
- constant-time analysis and manual data-flow review pass;
- focused tail benchmark and product-path intended benchmark move.

## Rejection Gates

Reject if any are true:

- simple sampling only detects a one-gate cheat with negligible probability;
- the batch check requires joined secret reconstruction;
- transcript openings reveal seed/scalar/share material outside approved
  branch-local ownership;
- implementation needs a second product runtime path with weaker exercise than
  the current Worker/WASM path;
- the first family benchmark does not move the product objective function.

## Expected Outcome

This is the only remaining idea with a credible path to a `~200ms` HSS-class
result under standard seed export, but it buys latency by changing the security
model. If this is rejected, the practical target for the current protocol is
probably `300ms-400ms` through E1/E2/E4/E5-style representation and root work,
and product latency work should shift toward the non-HSS registration tail and
unlock/session frequency.

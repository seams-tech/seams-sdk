# Production Privacy Formal Verification

## Purpose

This document tracks the work required to turn the current passive-security
composition evidence into a production privacy claim for `ed25519-yao`.

The first target is deliberately narrow:

> For a successful production export execution with one static passive
> corruption of Deriver A, the corrupted party's protocol-level view is
> computationally indistinguishable from a simulated view constructed from
> Deriver A's private inputs, its authorized export package share, declared
> public leakage, and independent simulator randomness.

Completing this target establishes export privacy against passive Deriver A.
It does not establish privacy for Deriver B, activation, colluding Derivers,
active corruption, adaptive corruption, concurrent composition, timing,
memory access, erasure, or undeclared transport metadata.

## Current Checkpoint

The repository currently provides:

- a complete typed passive view containing corrupted inputs and random tape,
  authorized package shares, payload-bearing messages, local-state snapshots,
  ordered messages, and transcript bytes;
- an export Deriver A simulator-input constructor with exact typed leakage;
- a generated production bridge for public directions, message kinds, payload
  lengths, frame counts, and ordering;
- finite all-distinguisher acceptance-count bounds;
- additive composition of five supplied adjacent-hybrid bounds;
- definition-level independence of the ideal simulator from honest private
  inputs and real-execution coins; and
- runtime conformance and public-shape checks over the committed boundary
  corpus.

`YAO-PRIV-001` is therefore conditional composition evidence. The five
transition bounds are premises. Production payload semantics, probabilistic
games, primitive reductions, and a nonvacuous final advantage bound remain
open under `YAO-SEC-002`.

## Claim Boundary

The initial proof covers:

- the production export family;
- Deriver A as the single statically corrupted party;
- honest protocol execution by both Derivers;
- the successful terminal path;
- the exact fixed production circuit, OT counts, message codecs, stream
  framing, transcript construction, and package-share format; and
- protocol-level observations explicitly represented by the typed view.

The initial proof excludes:

- Deriver A and Deriver B collusion;
- malicious or active deviations;
- adaptive corruption;
- selective failure and abort leakage;
- concurrent or interleaved sessions;
- timing, cache, allocation, memory-remanence, and erasure claims;
- host, process, transport, and Router metadata outside the declared public
  leakage; and
- compromise or incorrect implementation of trusted cryptographic primitives.

Any production statement must repeat these boundaries. Broader wording
requires the corresponding extensions listed later in this document.

## Milestone 1: Probabilistic Security Games

Replace the supplied finite sample multiset with games that sample the actual
coin distributions.

### Tasks

1. Define the fixed security parameter and production parameter set.
2. Define typed distributions for:
   - corrupted Deriver A randomness;
   - honest Deriver B randomness;
   - protocol and session identifiers;
   - base-OT randomness;
   - OT-extension randomness;
   - garbling labels and delta;
   - output-label randomness; and
   - simulator randomness.
3. Define the production real experiment.
4. Define the ideal experiment and its permitted leakage.
5. Define a distinguisher over the complete typed view.
6. Define advantage as the absolute difference between real and ideal
   acceptance probabilities.
7. Choose one proof target:
   - a concrete bound for the fixed production parameters; or
   - an asymptotic PPT and negligibility definition.

The preferred first target is a concrete bound. The protocol and its security
parameter are fixed, and the final release claim needs a numerical result.

### Completion Criteria

- Real and ideal coins are sampled inside the games.
- The distinguisher cannot choose or observe hidden game coins.
- Real and ideal experiments expose the same declared leakage type.
- The advantage definition cannot be satisfied by choosing an arbitrary
  relation.
- The game definitions build without project-owned admitted declarations.

## Milestone 2: Production Real-View Refinement

Bind the real experiment to the production Rust implementation.

### Tasks

1. Introduce one production view projection for export Deriver A.
2. Make production randomness explicit at a narrow internal boundary while
   retaining OS randomness at the public runtime boundary.
3. Project the corrupted view from the actual execution path:
   - Deriver A's `y_client` and `y_server`;
   - Deriver A's complete random tape;
   - every sent and received encoded message in order;
   - all corrupted-party local state retained across protocol transitions;
   - transcript updates and terminal transcript bytes;
   - success state; and
   - the authorized export package share.
4. Connect the projection to:
   - `WireMessage` encoding and decoding;
   - base-OT state transitions;
   - IKNP extension;
   - direct and masked input labels;
   - stream manifests and Half-Gates frames;
   - output translation and returned output labels;
   - transcript construction;
   - session and domain separation; and
   - export package construction.
5. Extend the Aeneas boundary or add a smaller proof-oriented Rust semantics
   bridge for the pure projection helpers.
6. Prove that the production projection equals the Lean real-game view.

The bridge must reuse the production implementation. A verification-only copy
of the protocol would provide conformance evidence rather than refinement.

### Completion Criteria

- Every byte in the real game has a production source.
- Every production observation covered by the claim appears in the typed view.
- Message order, direction, kind, length, payload, and transcript updates are
  preserved.
- Rust regeneration and Lean compilation are part of `cargo yao-fv`.
- Mutating a production codec, transition, transcript rule, or projection
  causes the refinement gate to fail.

## Milestone 3: Concrete Export-A Simulator

Instantiate the currently abstract simulator components.

### Tasks

1. Simulate the base-OT offer received from Deriver B.
2. Simulate the OT-extension matrix received from Deriver B.
3. Simulate honest-party label material visible to Deriver A.
4. Construct the corrupted garbler's local state and sent garbling material
   from Deriver A's input, permitted leakage, and simulator coins.
5. Simulate returned output labels.
6. Reconstruct ordered messages and transcript bytes.
7. Produce the exact authorized export package-share view.
8. Prove that the simulator reads only:
   - Deriver A's `y_client`;
   - Deriver A's `y_server`;
   - Deriver A's corrupted random tape;
   - the authorized export package share;
   - declared public leakage; and
   - independent simulator coins.

### Completion Criteria

- No honest Deriver B input or real-execution coin reaches the simulator.
- The simulator produces the exact production message and state schema.
- Public directions, kinds, lengths, frame count, and order match production.
- The ideal transcript is a deterministic function of simulated messages and
  declared public values.
- The authorized output is typed and linked to the export ideal functionality.

## Milestone 4: Primitive Reductions

Replace each whole-transition premise with a checked reduction to the exact
production construction and named cryptographic assumption.

### Base OT

- State the required Ristretto discrete-log or DDH-style assumption precisely.
- Model the exact point encoding, hash inputs, session binding, and role
  assignment.
- Reduce the real and simulated base-OT views to that assumption.

### IKNP OT Extension

- Model the exact matrix dimensions, bit order, PRG or hash construction, and
  selected-message count.
- Reduce the OT-extension hybrid to base-OT security and the exact
  correlation-robustness or random-oracle assumptions used by production.

### Input Labels

- Prove pseudorandomness of honest-party labels.
- Preserve the exact direct-label and masked-label ordering.
- Account for Free-XOR delta secrecy and every domain-separated derivation.

### Half-Gates Garbling

- Bind the proof to the exact fixed-key AES or hash construction.
- Model gate tweaks, circuit identity, wire ordering, and the production
  Half-Gates table encoding.
- Reduce simulated garbling to the stated correlation-robust hash assumption.

### Output Translation and Package Share

- Prove output-label simulation for the exact output-wire order.
- Connect returned labels and output translation to the authorized export
  package share.
- Prove that no additional honest-party value is exposed through package or
  transcript construction.

### Completion Criteria

- Every hybrid transition is derived rather than supplied as a whole-game
  premise.
- Each remaining assumption names its primitive, construction, domain,
  parameter, and dependency boundary.
- The reduction applies to the production-refined view.
- No transition can be discharged with a vacuous or unconstrained bound.

## Milestone 5: Quantitative Composition

Compute a nonvacuous final advantage for the fixed export circuit.

### Tasks

1. Count the exact production uses of:
   - base OTs;
   - extended OTs;
   - PRG and hash invocations;
   - input labels;
   - AND gates and Half-Gates hashes;
   - output labels; and
   - session identifiers and collision-sensitive values.
2. State the bad events and their probabilities.
3. Compose the primitive bounds with the checked hybrid theorem.
4. Evaluate the bound at the fixed production parameters.
5. Compare the result with the project's required security target.

A representative final form is:

```text
Adv_export_A
  <= Adv_base_ot
   + Adv_iknp
   + q_label * Adv_label_prf
   + q_gate * Adv_half_gates_hash
   + Adv_output
   + Pr[session collision or other bad event]
```

### Completion Criteria

- Every coefficient comes from a checked production constant or circuit
  metric.
- The final bound evaluates to a concrete value.
- The value meets the documented project security target.
- Changing a relevant circuit or protocol count invalidates the bound.

## Milestone 6: Claim and Review

### Tasks

1. Add a new proof obligation for the production export-A privacy theorem.
2. Keep `YAO-PRIV-001` as the general conditional composition obligation.
3. Record every cryptographic and implementation assumption in the assumption
   ledger.
4. Add regeneration and proof checks to `cargo yao-fv`.
5. Add mutation checks for the production view bridge and quantitative counts.
6. Obtain an independent cryptographic review of:
   - the real and ideal games;
   - declared leakage;
   - the simulator;
   - primitive assumptions and reductions;
   - quantitative composition; and
   - the final claim wording.

### Completion Criteria

The repository may claim production export privacy against passive Deriver A
only when:

- the randomized games are checked;
- the real game refines the actual Rust execution view;
- the concrete simulator is checked;
- all hybrid transitions follow from named primitive assumptions through
  checked reductions;
- the final advantage bound is nonvacuous and meets the target;
- the complete gate passes from a clean checkout; and
- independent review has approved the claim and its exclusions.

## Later Extensions

After the export Deriver A theorem is complete, extend the proof in this order:

1. export Deriver B;
2. activation Deriver A;
3. activation Deriver B;
4. passive abort and selective-failure leakage;
5. concurrent session composition;
6. Router and transport metadata;
7. adaptive corruption;
8. active security; and
9. timing, memory-access, and erasure properties.

Each extension requires its own claim boundary, simulator interface, production
refinement, primitive reductions, and composed bound.

## Critical Path

The production claim depends on one uninterrupted proof chain:

```text
probabilistic games
  -> production Rust real-view refinement
  -> concrete export-A simulator
  -> primitive reductions
  -> quantitative bound
  -> independent review and claim approval
```

Structural checks, finite conformance tests, and public-shape generation remain
valuable supporting evidence. They do not substitute for any link in this
chain.

# Passive Security Conditional Composition V1

## Claim

This artifact is a conditional hybrid-composition scaffold for the fixed
activation and export protocol families under one passive Deriver corruption.
It does not establish privacy of the production protocol.

The checked Lean result says that five supplied adjacent-hybrid bounds add to
an end-to-end bound. Each bound is stated against an explicit finite
distinguishing experiment: a distinguisher maps a complete typed observed view
to a Boolean, and its advantage numerator is the difference between acceptance
counts over the same finite sample multiset. The definition quantifies over all
distinguishers, which is a concrete statistical condition.

No bound is discharged for a production primitive. A large or vacuous supplied
bound makes the conditional conclusion correspondingly weak.

## Corruption Scope

The model has one static passive corruption:

- Deriver A; or
- Deriver B.

Deriver A and Deriver B collusion, Router coalitions, adaptive corruption,
active deviation, selective failure, timing, memory access, and erasure remain
outside this model.

## Complete Typed View

The observed view now contains:

- the corrupted Deriver's role-specific private inputs as typed byte values;
- the corrupted Deriver's random tape;
- exact authorized package-share types selected by protocol family;
- typed sent and received message shapes with payload bytes;
- component-tagged local-state snapshots;
- ordered messages and transcript bytes; and
- the generated production public view.

The authorized-output interface no longer accepts one unrestricted natural
number. Activation exposes exactly its Client and SigningWorker package shares;
export exposes exactly its export package share.

## Simulator

`passiveIdealSimulator` constructs the ideal view solely from
`PassiveSimulatorInput` and simulator coins. The ideal game is definitionally
independent of honest private inputs and real-execution coins.

`exportDeriverASimulator` is the narrow concrete simulator constructor. Its
typed leakage contains only Deriver A's `y_client`, `y_server`, export package
share, and corrupted random tape. Lean checks that the constructor uses the
generated `exportDeriverAView`.

This closes the export-A leakage and public-projection slice. The simulator's
five payload components still come from abstract component simulators.

## Hybrid Sequence

The composition scaffold uses:

1. real execution;
2. ideal base OT;
3. ideal OT extension;
4. simulated input labels;
5. simulated garbling; and
6. ideal simulated output.

`PassiveHybridTransitionAssumptions` supplies an explicit acceptance-count
bound for each adjacent transition. Lean proves the final bound is their sum
for activation/export and Deriver A/B.

These are whole-transition premises. The model does not present them as
primitive reductions.

## Production Linkage

`RuntimePublicShape.lean` is generated from successful production
local-protocol executions. `cargo yao-fv lean-check` regenerates it in memory
and requires byte equality with the committed source.

The generated boundary covers exact role-local direction, message kind,
payload length, and frame count for:

- activation Deriver A;
- activation Deriver B;
- export Deriver A; and
- export Deriver B.

The Rust runtime gate checks the same projections across twelve boundary and
deterministic generated input cases.

Production payload bytes, random-tape semantics, and internal-state
transitions have no extraction bridge into `PassiveProtocolSemantics`.

## Remaining Critical Proof

The next security milestone is one payload-level production refinement for
export Deriver A:

1. extract or otherwise prove the Rust real-view projection;
2. instantiate the five component simulators;
3. reduce each adjacent transition to the exact OT, hash, and garbling
   assumptions with concrete bounds; and
4. connect package-share leakage to the export ideal functionality.

Until those steps are complete, `YAO-SEC-002` remains pending and no deployed
passive-security claim is justified.

## Commands

```sh
cargo yao-fv passive-security-check
UPDATE_ED25519_YAO_RUNTIME_PUBLIC_SHAPE=1 cargo yao-fv lean-check
```

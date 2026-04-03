# Formal Verification Plan (Lean 4)

Last updated: 2026-04-03

## Goal

Use Lean 4 to formally verify security-critical cryptographic logic in Rust, focusing on our own composition/orchestration code and deterministic encoding paths in `signer-core` and on the low-level fixed-function expansion pipeline in `ed25519-hss`. Use Aeneas for Rust-to-Lean translation and Leanstral for LLM-assisted proof acceleration.

## Constraints

- No legacy verification tracks or deprecated proof targets.
- Breaking changes are acceptable during development if they improve proofability and remove obsolete code paths.
- Proof scope must be explicit about trusted dependencies vs verified code.

## Verification Boundary

### In scope (prove)

- Deterministic encoding + hashing logic:
  - `crates/signer-core/src/codec.rs`
  - `crates/signer-core/src/eip1559.rs`
  - `crates/signer-core/src/tempo_tx.rs`
- secp256k1 scalar/share mapping and signature invariants:
  - `crates/signer-core/src/secp256k1.rs`
  - `crates/signer-core/src/threshold_ecdsa.rs`
- Ed25519/FROST 2-party algebra and participant-id invariants:
  - `crates/signer-core/src/near_threshold_frost.rs`
  - `crates/signer-core/src/near_threshold_ed25519.rs`
- `ed25519-hss` fixed-function expansion spec and circuit-equivalence targets:
  - `crates/ed25519-hss/src/reference.rs`
  - `crates/ed25519-hss/src/candidate.rs`
  - `crates/ed25519-hss/src/artifact/prime_order_encoder.rs`
  - `crates/ed25519-hss/src/ddh/hidden_eval.rs`
  - `crates/ed25519-hss/src/ddh/hidden_eval_executor.rs`

### Out of scope (trusted assumptions)

- Internal correctness of third-party cryptography crates:
  - `k256`
  - `curve25519-dalek`
  - `frost-ed25519`
  - `threshold-signatures` (pinned rev)
  - `sha2`
- Browser runtime, network transport, and relay durability semantics.

## What Formal Verification Covers vs Testing

- Formal verification in this plan targets both:
  - cryptographic/algebraic correctness of the targeted protocol math, and
  - implementation-level correctness properties of our Rust code for those targets (for example deterministic encoding/hash preimages, signature-finalize invariants, share-mapping relations, and reject/accept conditions at protocol composition boundaries).
- Aeneas translates our Rust code into Lean 4 functional specs, so proofs operate over representations derived from the actual implementation rather than hand-written models.
- Formal verification does not replace integration/E2E testing. We still use integration/E2E suites to validate runtime behavior not modeled in Lean, including:
  - network transport behavior, retries, and ordering effects,
  - relay/store durability behavior and operational failure modes,
  - process/runtime wiring across WASM/server/client boundaries.
- For `ed25519-hss`, this plan proves the fixed-function expansion spec and its encoded hidden-eval realization. It does not attempt to prove end-to-end distributed transport, OT message delivery, or runtime scheduling semantics.
- Lean-generated vector parity tests are the bridge between model and implementation for in-scope functions: they detect byte-level divergence between proofs and Rust behavior.

## Specification Sources and Weighting

We use a weighted source hierarchy so proofs follow the exact implementation we run.

## Tier 0 (highest): Pinned implementation specs

### `signer-core` threshold behavior

Authoritative for threshold ECDSA behavior because our code is pinned to:

- `crates/signer-core/Cargo.toml` (`threshold-signatures` rev `db609be5021eb9d794f577601f422818fbdfe246`)
- `wasm/eth_signer/Cargo.toml` (`threshold-signatures` rev `db609be5021eb9d794f577601f422818fbdfe246`)

Primary references (pinned commit links):

- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/benches/model.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/confidential_key_derivation/confidential_key_derivation.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/crypto/proofs.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/preliminaries.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/orchestration.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/ot_based_ecdsa/triples.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/ecdsa/robust_ecdsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/eddsa/signing.md`
- `https://github.com/near/threshold-signatures/blob/db609be5021eb9d794f577601f422818fbdfe246/docs/dkg.md`

Notes on weighting:

- For ECDSA proofs, `ot_based_ecdsa` docs are primary.
- `robust_ecdsa` docs are reference-only unless/until implementation switches.
- `benches/model` and `confidential_key_derivation` are contextual references, not normative protocol behavior for current signer-core APIs.

### `ed25519-hss` fixed-function behavior

Authoritative for `ed25519-hss` fixed-function expansion behavior is the local Rust implementation and its explicitly encoded circuit pipeline:

- `crates/ed25519-hss/src/reference.rs`
- `crates/ed25519-hss/src/candidate.rs`
- `crates/ed25519-hss/src/artifact/prime_order_encoder.rs`
- `crates/ed25519-hss/src/artifact/prime_order_decoder.rs`
- `crates/ed25519-hss/src/ddh/hidden_eval.rs`
- `crates/ed25519-hss/src/ddh/hidden_eval_executor.rs`

Notes on weighting:

- `reference.rs` is the functional spec for `F_expand`.
- `candidate.rs`, artifact encoding/decoding, and hidden-eval compilation define the circuit shape and context binding.
- The executor path is proven equivalent to the `reference.rs` spec at the abstraction boundary we actually run.

## Tier 1: Standards-level references

- RFC 9591 (FROST): `https://datatracker.ietf.org/doc/html/rfc9591`
- RFC 8032 (Ed25519): `https://datatracker.ietf.org/doc/html/rfc8032`

These constrain Ed25519/FROST semantics where applicable and resolve ambiguity in secondary docs.

## Tier 2: Cait-Sith origin docs (secondary/background)

Useful for rationale and lineage, but lower priority than pinned `near/threshold-signatures` docs:

- `https://github.com/cronokirby/cait-sith/blob/main/docs/key-generation.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/orchestration.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/proofs.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/signing.md`
- `https://github.com/cronokirby/cait-sith/blob/main/docs/triples.md`

## Conflict Resolution Policy

- If sources disagree, use this precedence:
  - Pinned `near/threshold-signatures` docs + pinned code semantics
  - RFC constraints (for Ed25519/FROST semantics)
  - Cait-Sith docs
- Every theorem in `formal-verification/docs/proof-inventory.md` must declare a source class and cite at least one primary source. Aeneas-generated Lean definitions should reference the source Rust function path.
- Tier 0 citation is required for theorem targets that depend on `threshold-signatures` behavior.
- Local encoding/hash theorems may use local Rust implementation semantics as the primary source class, with standards references when applicable.

## Proof Objectives (Priority)

## P0 (must prove first)

- Share-mapping correctness for 2-party ECDSA:
  - `map_additive_share_to_threshold_signatures_share_2p` preserves additive secret under expected Lagrange factors.
- ECDSA finalize invariants:
  - final `r,s,recid` signature verifies against expected public key.
  - low-`s` normalization invariant holds.
- Deterministic tx digest and signed encoding:
  - EIP-1559 hash preimage correctness and serialization determinism.
  - Tempo sender-hash and signed payload serialization determinism.
- `ed25519-hss` fixed-function expansion circuit equivalence:
  - `eval_f_expand` output relation is proven from the clear spec.
  - artifact materialization and hidden-eval compilation are deterministic and context-bound.
  - the compiled hidden evaluator computes the same `FExpandOutput` fields as the clear spec for the fixed function.

## P1

- FROST 2-party group key reconstruction from verifying shares is algebraically correct.
- Participant-id validation invariants prevent ambiguous signer-set behavior.
- Non-zero scalar constraints are preserved through deterministic derivation paths.
- `ed25519-hss` share-recovery and public-key projection relations hold:
  - `recover_a_from_base_shares(x_client_base, x_relayer_base) = a`
  - `public_key_from_base_shares(...) = public_key_from_scalar_bytes(a)`

## P2

- Additional protocol-state invariants around presign/session transitions.
- Extended model checks for cosigner polynomial helpers and Lagrange-at-zero helper APIs.

## Phased Plan

## Phase 0: Lock Model and Threat Contract

- [ ] Write a formal model boundary doc:
  - trusted assumptions
  - attacker model
  - security and correctness properties
- [ ] Freeze canonical theorem names and mapping to Rust functions.
- [ ] Freeze spec source mapping in `formal-verification/docs/proof-inventory.md`:
  - theorem -> Rust function
  - theorem -> Tier 0 source URL(s)
  - supporting Tier 1/Tier 2 URLs when used
- [ ] Define pass/fail criteria for each property class (P0/P1/P2).

Definition of done:

- Every proof target has an unambiguous Rust function mapping and acceptance criterion.

## Phase 1: Create Formal Workspace

- [ ] Create top-level workspace:
  - `formal-verification/lean`
  - `formal-verification/vectors/generated`
  - `formal-verification/scripts`
  - `formal-verification/docs`
- [ ] Add Lean 4 build files (`lakefile.lean`, `lean-toolchain`) and deterministic tooling entrypoints.
- [ ] Set up Aeneas and Charon to translate target `signer-core` and `ed25519-hss` modules into Lean 4.
- [ ] Add `formal-verification/docs/proof-inventory.md` with theorem coverage table.

Definition of done:

- `lake build` runs in CI on at least one starter theorem and inventory exists.
- Aeneas successfully translates at least one target Rust module into Lean 4.

## Phase 2: Verify Encoding and Hashing (P0)

- [ ] Use Aeneas to translate `codec.rs`, `eip1559.rs`, and `tempo_tx.rs` into Lean 4.
- [ ] Prove hex/decimal/rlp primitives (`codec.rs`) used by signing pipelines.
- [ ] Prove EIP-1559 hash and signed-transaction encoding relations (`eip1559.rs`).
- [ ] Prove Tempo sender-hash and signed-payload encoding relations (`tempo_tx.rs`).
- [ ] Use Leanstral to accelerate tactic proofs for encoding determinism lemmas.
- [ ] Export Lean-generated vectors to `formal-verification/vectors/generated/*.json`.
- [ ] Add/extend Rust parity tests in:
  - `crates/signer-core/tests/baseline_behavior.rs`
  - `crates/signer-core/fixtures/signing-vectors/`

Definition of done:

- Rust vector tests fail on any encoding/hash divergence from Lean-generated vectors.

## Phase 3: Verify secp256k1 Share Algebra and Signature Invariants (P0/P1)

- [ ] Use Aeneas to translate `secp256k1.rs` into Lean 4, axiomatizing `k256` calls as trusted specs.
- [ ] Prove 2-party share mapping algebra:
  - inverse-Lagrange mapping recovers original additive share.
  - mapped share is in valid non-zero scalar range.
- [ ] Prove `sign_secp256k1_recoverable` invariants:
  - output length/shape.
  - low-`s` behavior and recovery-id consistency constraints.
- [ ] Prove key relation invariants for public-key addition/address derivation helpers.
- [ ] Use Leanstral to accelerate tactic proofs for algebraic lemmas (group laws, Lagrange interpolation linearity).

Definition of done:

- Required theorems for `secp256k1.rs` are proven and covered by generated-vector parity tests.

## Phase 4: Verify Threshold ECDSA Composition (P0)

- [ ] Use Aeneas to translate `threshold_ecdsa.rs` into Lean 4, axiomatizing `threshold-signatures` calls as trusted specs.
- [ ] Model presign + rerandomization composition at the abstraction boundary used by `threshold_ecdsa.rs`.
- [ ] Prove signature-share combination formula corresponds to final signature equation.
- [ ] Prove finalize step rejects invalid combinations and accepts valid ones under model assumptions.

Definition of done:

- Formal model proves the finalize path cannot emit an accepting signature that violates equation checks.

## Phase 5: Verify `ed25519-hss` Fixed-Function Expansion Circuit (P0/P1)

- [ ] Use Aeneas to translate `crates/ed25519-hss/src/reference.rs` into Lean 4, axiomatizing `sha2` and `curve25519-dalek` calls as trusted specs.
- [ ] Prove the clear `F_expand` spec:
  - add-mod-`2^256` relation for `m`,
  - SHA-512/clamp/reduce relation for `a_bytes` and `a`,
  - output-share projection equations for `tau`, `x_client_base`, and `x_relayer_base`,
  - public-key derivation relation for `public_key`.
- [ ] Translate the circuit-shaping modules:
  - `crates/ed25519-hss/src/candidate.rs`
  - `crates/ed25519-hss/src/artifact/prime_order_encoder.rs`
  - `crates/ed25519-hss/src/ddh/hidden_eval.rs`
- [ ] Prove artifact materialization and hidden-eval compilation are deterministic and context-bound for a fixed canonical context.
- [ ] Prove the hidden-eval stage inventory and ordering cover the intended fixed function:
  - add-mod-`2^256`,
  - SHA-512 schedule/round stages,
  - clamp/reduce stage,
  - output projector stage.
- [ ] Prove the hidden evaluator implements the same output relation as `eval_f_expand` at the `FExpandOutput` boundary.
- [ ] Export Lean-generated vectors to `formal-verification/vectors/generated/ed25519-hss/*.json`.
- [ ] Add/extend Rust parity tests in `crates/ed25519-hss/tests/` to fail on any divergence between Lean-generated vectors, the clear reference path, and the compiled hidden-eval path.

Definition of done:

- The fixed-function expansion circuit is proven equivalent to the clear `reference.rs` spec at the output boundary we expose in Rust.

## Phase 6: Verify Threshold Ed25519/FROST 2P Algebra (P1)

- [ ] Use Aeneas to translate `near_threshold_frost.rs` and `near_threshold_ed25519.rs` into Lean 4, axiomatizing `frost-ed25519` and `curve25519-dalek` calls as trusted specs.
- [ ] Prove group-public-key reconstruction from verifying shares and participant IDs.
- [ ] Prove round-2 cosigner share algebra corresponds to modeled challenge equation.
- [ ] Prove participant-id constraints eliminate degenerate denominators and invalid signer sets.
- [ ] Consult Symcrust (AeneasVerif) Lean 4 crypto patterns for elliptic curve formalizations.

Definition of done:

- Theorems cover core Ed25519 threshold key/share math in current production path.

## Phase 7: CI and Change Management

- [ ] Add CI job:
  - `lake build` proof build
  - Lean 4 kernel type-check (implicit in `lake build`)
  - fail on `sorry` usage in theorem files
  - fail on unaxiomatized `axiom` declarations outside the trusted-dependency boundary
  - vector export consistency check
  - Rust parity tests
  - Aeneas re-translation check: fail if Rust source changes produce different Lean output without proof updates
- [ ] Add guard script preventing Rust crypto-function changes without proof-inventory updates.
- [ ] Document workflow for updating proofs when dependencies or function signatures change, including re-running Aeneas translation.

Definition of done:

- PRs cannot merge when proofs/vectors are out of sync with Rust implementation.

## Deliverables

- `docs/formal-verification.md` (this plan)
- `formal-verification/docs/model-boundary.md`
- `formal-verification/docs/proof-inventory.md`
- `formal-verification/lean/**` theorem files and Aeneas-generated Lean translations
- `formal-verification/vectors/generated/*.json`
- Updated `signer-core` and `ed25519-hss` vector fixtures + parity tests
- CI gate for formal + parity checks
- Aeneas/Charon configuration for reproducible Rust-to-Lean translation

## Tooling Evaluation: Lean 4 vs Coq (2026-03-18)

Phase 0 and Phase 1 have not started yet. Before committing to a proof assistant, we evaluated two tools that change the cost/benefit landscape and compared Lean 4 against the original Coq plan.

### Aeneas (AeneasVerif/aeneas)

Aeneas is a verification toolchain that translates Rust programs into pure functional representations in proof assistants. It compiles Rust source via Charon into an intermediate representation (LLBC), then functionalizes it — eliminating mutable borrows and imperative control flow — into idiomatic proof assistant code.

Key facts:

- **Backends:** Lean 4 (most mature), HOL4, Coq, F*.
- **Rust support:** Safe Rust: structs, enums, traits, mutable borrows, loops. No unsafe code, no concurrency, no `return` inside nested loops.
- **Maturity:** 4,900+ commits, 28 contributors, 631 GitHub stars. Translation soundness formally proved and published at ICFP 2022, with follow-up borrow-checking soundness proof in 2024.
- **Ecosystem:** The AeneasVerif org also maintains Symcrust (verified Rust reimplementation of ML-KEM crypto primitives with Lean proofs) and Eurydice (compiles verified Rust to C).

Applicability to our verification targets:

| Target | Fit | Notes |
| --- | --- | --- |
| `codec.rs`, `eip1559.rs`, `tempo_tx.rs` (encoding) | Excellent | Pure safe Rust. Translate directly, prove determinism and round-trip properties. |
| `secp256k1.rs` share mapping | Good | Translate our composition code, axiomatize `k256` calls as trusted specs. Matches our existing trust boundary. |
| `threshold_ecdsa.rs` finalize | Good | Same pattern: prove orchestration, trust `threshold-signatures` internals. |
| `near_threshold_frost.rs` FROST algebra | Good | Algebraic properties are well-suited to functional translation. |
| `ed25519-hss` fixed-function expansion | Good | Best handled as clear-spec plus circuit-equivalence proofs, with `sha2` and `curve25519-dalek` calls trusted. |

Key limitation: cannot cross C FFI boundaries. Our plan already treats `k256`, `curve25519-dalek`, `frost-ed25519`, and `threshold-signatures` as trusted assumptions, so this aligns.

### Leanstral (Mistral AI)

Leanstral is an open-source LLM (120B MoE, 6B active parameters) trained specifically for Lean 4 proof generation. Apache 2.0, self-hostable.

Key facts:

- **Target:** Lean 4 only.
- **Capability:** Generates Lean 4 tactic proofs and checks them against the kernel. Achieves 26.3 pass@2 on FLTEval.
- **Maturity:** Released March 2026. Available as downloadable weights and API endpoint.
- **Use case:** Accelerates writing algebraic lemmas (group associativity, Lagrange interpolation linearity, low-s normalization). Every proof must still typecheck in Lean 4's kernel, so there is no trust issue.
- **Limitation:** It is an LLM, not a solver. May fail on non-trivial crypto lemmas. Productivity multiplier, not a replacement for manual proof work.

### Lean 4 vs Coq comparison

| Dimension | Coq | Lean 4 |
| --- | --- | --- |
| **Rust translation** | Aeneas supports Coq backend, but Lean backend is most mature and best maintained. | Aeneas Lean backend is primary. Symcrust crypto verification uses Lean. |
| **LLM proof acceleration** | No production-quality Coq-specific proof LLM available. | Leanstral is purpose-built for Lean 4 tactic proofs. |
| **Existing crypto libraries** | Fiat-Crypto (field arithmetic, verified C/Rust output). Coqprime. Mature elliptic curve formalizations. | Lean 4 crypto library ecosystem is smaller but growing. Mathlib has group/ring/field algebra. Symcrust is building crypto primitives. |
| **Language ergonomics** | Gallina is functional but verbose. Ltac/Ltac2 tactic languages have steep learning curve. | Lean 4 is a general-purpose functional language with tactic mode. Syntax is closer to mainstream languages. |
| **Build tooling** | `coqc`, `coqchk`, `opam`. Mature but slow compilation on large developments. | `lake` build system, faster incremental builds, better IDE integration (VS Code). |
| **Kernel trust** | Coq kernel is battle-tested over 30+ years. `coqchk` provides independent re-verification. | Lean 4 kernel is newer but formally specified. Type-theory foundations are well-understood. |
| **Community size** | Larger academic community, more published formalizations. | Rapidly growing community (Mathlib is one of the largest math formalizations in any system). |
| **CI integration** | Standard `coqc` + `coqchk` pipeline. | `lake build` + `lake env` pipeline. Lean 4 toolchain is Nix-friendly. |

### Assessment

Arguments for switching to Lean 4:

1. **Aeneas Lean backend is primary.** The Coq backend exists but receives less attention. Choosing Lean means working with the best-maintained translation path.
2. **Leanstral eliminates proof-writing bottleneck.** The tedious algebraic lemmas (our P0 and P1 targets) are exactly what Leanstral handles well. No equivalent exists for Coq.
3. **Symcrust precedent.** The same organization behind Aeneas is using Lean to verify real crypto primitives in Rust. This is directly analogous to our project and means the tooling gaps are being actively filled.
4. **Ergonomics.** Lean 4's syntax and IDE tooling reduce onboarding cost for contributors who are not proof-assistant specialists.
5. **Timing.** Phase 0 has not started. There is no sunk cost in Coq infrastructure.

Arguments for staying with Coq:

1. **Fiat-Crypto.** If we ever need verified field arithmetic (not currently in scope), Fiat-Crypto is Coq-only.
2. **Kernel maturity.** Coq's kernel has 30+ years of hardening. For a project verifying security-critical crypto, this matters.
3. **Existing formalizations.** More published elliptic curve and group theory formalizations exist in Coq.

### Decision

Switch from Coq to Lean 4.

Rationale:

- Our verification boundary explicitly trusts third-party field arithmetic and curve implementations. We are proving our own composition, orchestration, and encoding logic — not reimplementing `k256` or `curve25519-dalek`. This means Fiat-Crypto's advantage does not apply.
- The Aeneas + Leanstral pipeline provides an automated Rust-to-proof-obligation-to-proof workflow that does not exist for Coq. This directly addresses our biggest risk: proof maintenance burden slowing iteration.
- Symcrust demonstrates that Lean 4 crypto verification on Rust code is viable today, with an active team filling library gaps.
- Coq's kernel maturity advantage is real but marginal for our threat model. Lean 4's kernel is formally specified and the proofs are machine-checked regardless.

### Impact on plan

The switch affects Phase 1 onward:

- Phase 1: workspace uses `lake` instead of `coqc`/`_CoqProject`. Directory becomes `formal-verification/lean` instead of `formal-verification/coq`.
- Phase 2-5: proofs are written in Lean 4. Aeneas generates Lean translations of target Rust functions. Leanstral assists with tactic proofs.
- Phase 6: CI uses `lake build` + Lean kernel check. `Admitted`/`sorry` detection replaces `Admitted`/`Axiom` detection.
- Proof inventory references Lean theorem names instead of Coq theorem names.
- Vector export and Rust parity test strategy is unchanged.

### Tools summary

| Tool | Role | When to use |
| --- | --- | --- |
| Aeneas | Translate Rust → Lean 4 functional specs | Phase 1 onward: generate proof obligations from `signer-core` Rust code |
| Leanstral | LLM-assisted Lean 4 proof writing | Phase 2 onward: accelerate algebraic and encoding proofs |
| Charon | Rust MIR → LLBC frontend (used by Aeneas) | Automatically invoked by Aeneas |
| Symcrust | Reference project for crypto verification patterns | Ongoing: consult for Lean 4 crypto library patterns and elliptic curve formalizations |

## Risks and Mitigations

- Risk: Lean model diverges from Rust byte-level semantics.
  - Mitigation: Aeneas generates Lean specs from Rust source, reducing manual translation drift. Generated vectors serve as a hard parity oracle in Rust tests.
- Risk: Over-modeling third-party cryptography internals stalls progress.
  - Mitigation: keep strict assumption boundary; prove composition logic first. Axiomatize `k256`, `curve25519-dalek`, `frost-ed25519`, and `threshold-signatures` calls.
- Risk: Proof maintenance burden slows iteration.
  - Mitigation: Aeneas re-translation on Rust changes keeps specs in sync. Leanstral accelerates proof repair. Prioritize P0 theorem set and enforce proof-inventory ownership.
- Risk: Aeneas cannot translate some Rust patterns (unsafe, nested loop control flow).
  - Mitigation: our in-scope Rust modules are safe, pure computation. Validate Aeneas compatibility in Phase 1 pilot before committing.
- Risk: Lean 4 crypto library ecosystem is less mature than Coq's.
  - Mitigation: consult Symcrust for patterns. Axiomatize curve operations rather than re-formalizing them. Lean Mathlib provides the underlying algebra.

## Immediate Next Actions

- [ ] Install Lean 4 toolchain, Aeneas, and Charon. Validate Aeneas can translate at least one target `signer-core` module.
- [ ] Create `formal-verification/` skeleton with `lakefile.lean`, `lean-toolchain`, and Aeneas configuration in one PR.
- [ ] Run Aeneas on `crates/signer-core/src/secp256k1.rs` and review the generated Lean 4 output for completeness.
- [ ] Implement first pilot proof on:
  - `map_additive_share_to_threshold_signatures_share_2p` (using Aeneas-generated Lean spec, with `k256` calls axiomatized)
- [ ] Wire pilot proof output into `crates/signer-core/tests/baseline_behavior.rs`.
- [ ] Evaluate Leanstral on the pilot proof lemmas to calibrate LLM-assisted proof productivity.

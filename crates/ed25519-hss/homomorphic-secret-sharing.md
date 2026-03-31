# Homomorphic Secret Sharing for Succinct Garbling

Date updated: March 31, 2026

Primary paper:

- [A Unified Framework for Succinct Garbling from Homomorphic Secret Sharing (ePrint 2025/442)](https://eprint.iacr.org/2025/442)
- local PDF:
  [A_Unified_Framework_for_Succinct_Garbling_from_Homomorphic_Secret_Sharing_2025_442.pdf](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/A_Unified_Framework_for_Succinct_Garbling_from_Homomorphic_Secret_Sharing_2025_442.pdf)

## Bottom Line

This paper is relevant to this crate, but only as a design direction, not as a
drop-in protocol.

What it gives us:

- a generic way to build succinct garbling using HSS as the evaluation core
- prime-order-group instantiations that are conceptually close to our DDH/HSS
  backend
- a clean argument for why it can beat Yao on artifact size when the same
  garbled artifact is reused many times
- a path from Boolean succinct garbling to arithmetic garbling over `Z_R`

What it does not give us:

- our exact 2-party OT/HSS message flow
- our exact `d -> SHA-512(d) -> clamp -> a` fixed function
- our exact split/local executor model
- a ready-made replacement for the current `ddh_hss.rs` and
  `ddh_hidden_eval_executor.rs` implementation

So the right interpretation is:

- this paper validates the HSS-based succinct-garbling direction
- it does not replace the need for our fixed-function compiler, delivery path,
  and executor engineering

## Paper Summary

The paper's main idea is to replace heavier succinct-garbling machinery with
HSS-based evaluation procedures.

At a high level:

1. represent garbling so most of the public artifact is very compact
2. use HSS to evaluate gate relations rather than sending Yao-style encrypted
   tables
3. exploit circuit structure so amortized per-gate public size can approach
   `1` bit for Boolean circuits
4. extend the same framework to arithmetic circuits so mod-`p` arithmetic does
   not pay the usual `Omega(lambda)` multiplicative overhead

Important results from the paper:

- succinct Boolean garbling with about `1` bit per gate under circular
  assumptions
- leveled variants that avoid circular-security assumptions at the cost of a
  depth-dependent additive term
- arithmetic garbling over `Z_R` with size roughly `O(|C| * log R)` instead of
  the usual `Omega(lambda * log R)` style overhead
- prime-order instantiations

For our purposes, the most relevant parts are:

- the prime-order-group instantiation
- the HSS-as-evaluation-core viewpoint
- the arithmetic-garbling extension for mod-`l` style arithmetic

## What Is Relevant To Our Problem

Our fixed function is:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`
- `A = [a]B`

The paper is relevant in three places.

### 1. Succinct public artifact

The paper's real advantage is not "faster gate evaluation than Yao." It is
"much smaller reusable public garbling artifacts."

That maps directly to our crate's artifact work:

- [hidden_eval.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/hidden_eval.rs)
- [prime_order_encoder.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/prime_order_encoder.rs)
- [prime_order_decoder.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/prime_order_decoder.rs)

This is the strongest conceptual overlap.

### 2. HSS as the gate-evaluation mechanism

The paper treats HSS as the hidden-computation engine behind succinct
garbling.

That aligns with the role already played here by:

- [ddh_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hss.rs)

We already use:

- `KeyGen`
- hidden sharing
- hidden add
- hidden multiply
- split/local representations

So this crate is already closer to the paper's worldview than to Yao's GC.

### 3. Arithmetic projector work

The paper's arithmetic-garbling section is relevant to our output projector and
scalar-reduction tail:

- mod-`l` reduction
- base-share projection
- mixed Boolean/arithmetic boundaries

That maps most closely to:

- [ddh_hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hidden_eval_executor.rs)

This is not immediately reusable code, but it is a good guide for what a more
principled Boolean/arithmetic split could look like.

## What Is Not Directly Relevant

Several parts of the paper are not a direct fit for the current crate.

### Generic circuit focus

The paper is about general succinct garbling. We are building one fixed
function. That means our best wins come from fixed-function specialization, not
from implementing the paper literally.

### Label-centric garbling interface

The paper is still framed as a garbling scheme with garbler/evaluator labels.
Our runtime is already organized around explicit split/local hidden values and a
compiled fixed-function executor.

So the paper is better viewed as:

- a backend/theory reference

not:

- the exact API shape we should expose

### Assumption profile

The paper's best size results rely on circular variants of power assumptions.
It also offers leveled variants with a depth term.

For us, this means:

- if we borrow from the paper, the leveled variant is probably the cleaner
  security story
- our fixed one-block SHA-512 depth is bounded and known in advance, so a
  depth-dependent additive term may be acceptable

But this still requires fresh design work. It is not just a parameter swap in
the current code.

## How To Use This In The Crate

The paper suggests a concrete implementation direction for this crate:

### Phase 1. Keep the current fixed-function compiler

Do not replace the fixed-function compiler with a generic garbling frontend.

Keep:

- [reference.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/reference.rs)
- [hidden_eval.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/hidden_eval.rs)
- [prime_order_encoder.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/prime_order_encoder.rs)

The paper helps justify this because our circuit is fixed and reusable.

### Phase 2. Treat `ddh_hss.rs` as the paper-aligned core

If we want to bring the implementation closer to the paper, the central file is:

- [ddh_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hss.rs)

That is where a more paper-like HSS public-data / preprocessed-secret-key split
would belong.

In practical terms, the next paper-aligned refactor would be:

- make public artifact data more explicit as reusable gate/program data
- separate that from run-bound secret preprocessing more cleanly
- keep the split/local execution boundary intact

### Phase 3. Keep the current executor model

The executor should stay fixed-function and split/local:

- [ddh_hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh_hidden_eval_executor.rs)

The paper does not give us a reason to reopen joined execution or generic
label-based runtime objects.

### Phase 4. Use the arithmetic section selectively

The paper's arithmetic-garbling ideas are most useful for:

- mod-`l` reduction
- output-share projection
- reducing Boolean-to-arithmetic crossing cost

This is a narrower and more realistic use than trying to reframe the whole
SHA-512 core as arithmetic garbling.

## Recommended Interpretation For Future Work

If we build on this paper, the right next step is:

1. keep the current fixed-function succinct-HSS crate shape
2. tighten the separation between:
   - public reusable artifact data
   - per-session HSS preprocessing
   - evaluator-local split execution
3. explore whether the paper's arithmetic-garbling ideas can simplify the
   output projector and scalar reduction
4. only after that, consider whether a more literal succinct-garbling compiler
   structure is worth importing

## Recommendation

Keep this paper and this note.

Delete the older broader SHA-512 MPC research note.

Reason:

- this paper is the only one from that old note that is still directly relevant
  to the current succinct-HSS track
- the rest were mostly earlier alternative directions that no longer describe
  the implementation path we are actually pursuing

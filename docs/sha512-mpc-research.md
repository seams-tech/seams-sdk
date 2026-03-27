# SHA-512 MPC Research Notes

This note collects the papers discussed while evaluating hidden Ed25519 seed expansion:

- shared root shares over canonical seed `d`
- hidden conversion to `a = clamp(SHA-512(d)[0..31])`
- output as threshold/FROST signing shares
- without revealing `d` or `a` to either client or server

## Bottom line

I did not find a recent 2024-2025 paper that directly gives the exact protocol we want:

- shared Ed25519 seed `d`
- hidden `a = clamp(SHA-512(d)[0..31])`
- direct output as threshold/FROST shares

The closest direct precedent is older. The most promising recent directions are mixed Boolean/arithmetic MPC, edaBits-style Boolean-to-arithmetic conversion, and more efficient active-secure garbling backends.

## Closest direct precedent

### Thresholdizing HashEdDSA: MPC to the Rescue

- Paper: [ePrint 2020/214](https://eprint.iacr.org/2020/214)
- Authors: Charlotte Bonte, Nigel P. Smart, Titouan Tanguy
- Why it matters:
  - Closest direct precedent to the hidden `d -> a` problem.
  - Deals with MPC over EdDSA-style hashed secret material.
  - Explicitly highlights the hard part: evaluating the hash in MPC, then moving from bit-domain outputs into field-domain secret shares.
- Relevance to this project:
  - Best reference for "this is the hard part and here is why."
  - Strong evidence that the `SHA-512 + clamp` step is the main nonlinear bottleneck.

## Recent papers worth studying

### Stateless Deterministic Multi-Party EdDSA Signatures with Low Communication

- Paper: [ePrint 2024/358](https://eprint.iacr.org/2024/358)
- Authors: Qi Feng, Kang Yang, Kaiyi Zhang, Xiao Wang, Yu Yu, Xiang Xie
- Why it matters:
  - Recent threshold EdDSA work.
  - Uses `mv-edabits` to transform values from the Boolean domain into the arithmetic domain.
  - Shows a concrete recent direction for reducing communication in multi-party EdDSA.
- Relevance to this project:
  - Strongest recent hint that a mixed MPC design with edaBits/mv-edabits is more promising than treating the whole problem as a generic large garbled circuit.

### Efficient Arithmetic in Garbled Circuits

- Paper: [ePrint 2024/139](https://eprint.iacr.org/2024/139)
- Author: David Heath
- Why it matters:
  - Focuses on arithmetic-friendly garbling rather than pure Boolean-only arithmetic encoded through large Boolean circuits.
  - Useful for parts of the conversion that are naturally arithmetic.
- Relevance to this project:
  - Most relevant to the arithmetic parts around:
    - `y_client + y_relayer mod 2^256`
    - post-hash scalar processing
    - base-share arithmetic after the nonlinear hash step
  - Less directly useful for the SHA-512 compression logic itself.

### Coral: Maliciously Secure Computation Framework for Packed and Mixed Circuits

- Paper: [ePrint 2024/1372](https://eprint.iacr.org/2024/1372)
- Authors: Zhicong Huang, Wen-jie Lu, Yuchen Wang, Cheng Hong, Tao Wei, WenGuang Chen
- Why it matters:
  - Practical mixed-circuit MPC framework.
  - Explicitly uses `daBit` / `edaBit` style machinery.
  - Focused on malicious security and practical performance.
- Relevance to this project:
  - Strong candidate reference if we want a mixed Boolean/arithmetic fixed-function protocol rather than an all-Boolean circuit.

### Highly Efficient Actively Secure Two-Party Computation with One-Bit Advantage Bound

- Paper: [ePrint 2025/614](https://eprint.iacr.org/2025/614)
- Authors: Yi Liu, Junzuo Lai, Peng Yang, Anjia Yang, Qi Wang, Siu-Ming Yiu, Jian Weng
- Why it matters:
  - Recent work on very efficient actively secure 2PC.
  - Still garbling-oriented, but much closer to practical active security overheads.
- Relevance to this project:
  - Good reference if we keep a garbled-circuit backend and want better active-security engineering without changing the overall architecture.

### A Unified Framework for Succinct Garbling from Homomorphic Secret Sharing

- Paper: [ePrint 2025/442](https://eprint.iacr.org/2025/442)
- Authors: Yuval Ishai, Hanjun Li, Huijia Lin
- Why it matters:
  - Research direction for much smaller garbled circuits.
  - Shows how communication/storage can be reduced substantially in principle.
- Relevance to this project:
  - Interesting long-term direction if garbled circuit size remains the main blocker.
  - Probably too research-heavy for immediate implementation.

### Re-Randomized FROST

- Paper: [ePrint 2024/436](https://eprint.iacr.org/2024/436)
- Authors: Conrado P. L. Gouvea, Chelsea Komlo
- Why it matters:
  - Extends FROST with rerandomizable public and secret keys/shares.
- Relevance to this project:
  - Not a solution to hidden `d -> a`.
  - Still relevant once scalar-domain shares already exist and we want rerandomization behavior on top of FROST shares.

## Current assessment

If we stay pure-crypto and keep the invariant that neither side may ever see plaintext `d`, the most promising experimental direction is:

1. Boolean-domain handling for the fixed one-block RFC 8032 seed expansion.
2. Mixed Boolean/arithmetic conversion using `edaBits` / `mv-edabits` style techniques.
3. Field-domain output as hidden scalar shares or base FROST shares.

In other words:

- best direct precedent: `Thresholdizing HashEdDSA`
- best recent design clue: `Stateless Deterministic Multi-Party EdDSA Signatures with Low Communication`
- best mixed-circuit implementation clue: `Coral`
- best GC/arithmetic optimization clue: `Efficient Arithmetic in Garbled Circuits`
- best active-security backend clue: `Highly Efficient Actively Secure Two-Party Computation with One-Bit Advantage Bound`
- best longer-term small-garbling research clue: `A Unified Framework for Succinct Garbling from Homomorphic Secret Sharing`

## Recommendation order

If we come back to experimental hidden `d -> a` conversion research, investigate in this order:

1. Mixed Boolean/arithmetic MPC with `edaBits` / `mv-edabits`.
2. Improved active-secure GC backend for the nonlinear/hash-heavy core only.
3. Succinct-garbling research track only if communication remains the dominant blocker after the first two directions are explored.

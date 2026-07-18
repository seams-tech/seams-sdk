# Pinned NEAR fixed-path check inventory

Status: bounded Phase D source-to-target inventory. The source corpus is NEAR
`threshold-signatures` commit
`db609be5021eb9d794f577601f422818fbdfe246`, tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`. The oracle manifest pins every
source file cited below by SHA-256. This inventory covers the fixed two-role
triple, presign, rerandomization, and signing call graph selected by the
refactor. Generic multi-party branches outside that graph are excluded.

The classifications are:

- `full_match`: the purpose-built path preserves the check or equation;
- `code_stronger_than_source`: fixed types, canonical parsing, or terminal
  lifecycle rules remove a source ambiguity or panic surface;
- `deliberate_mismatch`: exact parity would preserve a known defect;
- `assumption`: the local code enforces the boundary while cryptographic or
  deployment security remains in the assurance ledger.

Every local receive transition consumes its prior state. Any returned error
therefore destroys the in-memory state at the API boundary. Durable Client and
SigningWorker adapters map an error, timeout, crash, or ambiguous delivery to
the one-use pool tombstone path.

## Boundary and transport checks

| ID       | Pinned source evidence                                                                                                              | Purpose-built owner and disposition                                                                                                                                                                                | Classification              | Confidence |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------: |
| `BND-01` | `ecdsa/mod.rs:94-103`; `protocol/internal.rs:330-340`                                                                               | `router-ab-ecdsa-wire` fixed arrays plus `presign/src/codec.rs:165-207` require exact digest, scalar, point, and frame widths before decoding                                                                      | `code_stronger_than_source` |       0.99 |
| `BND-02` | `ecdsa/mod.rs:176-180`; `ot_based_ecdsa/mod.rs:67-73`                                                                               | `presign/src/lib.rs:120-133,208-216` and `online/src/lib.rs:150-230` require canonical scalars and a non-zero private share; mathematically valid peer protocol values may be zero where their equation permits it | `full_match`                |       0.99 |
| `BND-03` | `presign.rs:25-57`; `sign.rs:30-61`; `participants.rs:128-194`                                                                      | Separate Client and SigningWorker constructors fix `N = t = 2`, coordinates, roles, and Lagrange coefficients; compile-fail fixtures reject generic topology                                                       | `code_stronger_than_source` |       1.00 |
| `BND-04` | `protocol/mod.rs:51-65`; generic protocol futures expose wait/send/return stages                                                    | `presign/src/driver.rs:324-871`, `presign/src/lib.rs:356-416`, and `pool/src/lib.rs:183-470` encode stage and one-use progression as consuming types                                                               | `code_stronger_than_source` |       1.00 |
| `MSG-01` | `protocol/internal.rs:286-295` silently drops short or unparseable 40-byte headers                                                  | `presign/src/codec.rs:165-207` returns a terminal error for every invalid 12-byte production header or length                                                                                                      | `code_stronger_than_source` |       1.00 |
| `MSG-02` | `protocol/internal.rs:58-64,330-340` propagates MessagePack encode/decode failures                                                  | `presign/src/codec.rs:165-207` and its role-specific decoders use one strict fixed-width canonical codec with allocation ceilings                                                                                  | `code_stronger_than_source` |       1.00 |
| `MSG-03` | `protocol/helpers.rs:15-24` ignores duplicate/unknown shared senders; `protocol/internal.rs:436-449` ignores a wrong private sender | Role-specific frames, exact expected round, context, and sender are checked before every consuming transition; duplicate, reflection, and wrong-role frames abort                                                  | `code_stronger_than_source` |       0.99 |
| `MSG-04` | `protocol/internal.rs:214-255` creates unbounded waitpoint queues and waits indefinitely                                            | The production driver accepts exactly one bounded frame for its current role/round; pool and transport owners impose terminal deadlines                                                                            | `code_stronger_than_source` |       0.96 |

## OT and multiplication checks

| ID       | Pinned source evidence                                                                                                                    | Purpose-built owner and disposition                                                                                                                    | Classification              | Confidence |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------: |
| `OT-01`  | `triples/batch_random_ot.rs:76-100,227-257` parses peer points before Diffie-Hellman operations                                           | `presign/src/triples/base_rot.rs:114-166,374-417,505-511` accepts only canonical non-identity points and rejects `X - Y = identity`                    | `code_stronger_than_source` |       0.98 |
| `OT-02`  | `triples/batch_random_ot.rs:100-110,176-197` transposes and validates 128-bit OT matrices                                                 | Fixed `[T; 128]` base-ROT state and sealed outputs encode the shape; malformed wire lengths fail before construction                                   | `code_stronger_than_source` |       0.98 |
| `OT-03`  | `triples/correlated_ot_extension.rs:18-49` checks correlation and received matrix heights                                                 | `presign/src/triples/base_rot/extension.rs` fixes 768 released and 1,024 padded rows in types and the codec                                            | `code_stronger_than_source` |       0.98 |
| `OT-04`  | `triples/random_ot_extension.rs:99-105` requires exactly 128 `small_t` columns                                                            | The local consistency proof contains a fixed 128-column array and cannot represent another length                                                      | `code_stronger_than_source` |       1.00 |
| `OT-05`  | `triples/random_ot_extension.rs:107-120` enforces every `q_j = t_j + Delta_j * x` equation                                                | `presign/src/triples/base_rot/extension.rs` accumulates all 128 equation results and releases sender/receiver outputs only after acceptance            | `full_match`                |       0.97 |
| `OT-06`  | `triples/bits.rs:320-327` hashes a base key into one hasher and finalizes a different unkeyed clone, making expanded rows key-insensitive | `presign/src/triples/base_rot/extension.rs:895-934` uses the selected base key in every row expansion; all 256 branches have sensitivity regressions   | `deliberate_mismatch`       |       1.00 |
| `MTA-01` | `triples/mta.rs:60-75,96-125` assumes a non-empty ciphertext vector and indexes `delta[0]`/`tv[0]` after one length check                 | `presign/src/triples/base_rot/extension/mta.rs` uses exactly 384 ciphertext pairs and fixed outputs; empty or wrong-size input cannot reach arithmetic | `code_stronger_than_source` |       0.99 |
| `MTA-02` | `triples/multiplication.rs:66-91,125-150,197-292` runs a non-zero batch and expects one result per peer and triple                        | The driver fixes two triples and both role directions; missing or excess results fail canonical round decoding                                         | `code_stronger_than_source` |       0.98 |

## Committed-triple checks

| ID       | Pinned source evidence                                                                                                                             | Purpose-built owner and disposition                                                                                                       | Classification              | Confidence |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ---------: |
| `TRI-01` | `triples/generation.rs:41-45,523-543,580-586,599-606` propagates transcript, degree, generation, evaluation, commitment, hash, and encoding errors | `presign/src/triples.rs`, `proofs.rs`, and `triples/finalize.rs` map the fixed equivalents to typed, secret-free terminal errors          | `full_match`                |       0.96 |
| `TRI-02` | `triples/generation.rs:567-575,621-685,721-787,854-884,971-1039` indexes generic peer vectors in the batched path                                  | Eleven fixed message structs contain exactly two triple slots where required; strict decoders validate complete sizes before construction | `code_stronger_than_source` |       0.99 |
| `TRI-03` | `triples/generation.rs:698-707` requires peer confirmations to equal the locally hashed ordered commitments                                        | Round 1/2 verification binds each commitment to scope, pair, role, and triple index before opening                                        | `code_stronger_than_source` |       0.98 |
| `TRI-04` | `triples/generation.rs:733-741` requires degrees `threshold-1`, `threshold-1`, `threshold-2`                                                       | `presign/src/triples.rs:70-158` structurally fixes degree one, degree one, and degree zero                                                | `code_stronger_than_source` |       1.00 |
| `TRI-05` | `triples/generation.rs:743-754` verifies the polynomial commitment opening                                                                         | `presign/src/triples.rs:624-650` verifies a role/context/index-bound opening with constant-time digest equality                           | `code_stronger_than_source` |       0.99 |
| `TRI-06` | `triples/generation.rs:755-779` verifies peer DLog proofs for `e_i(0)` and `f_i(0)`                                                                | `presign/src/proofs.rs` provides fixed proof kinds with role, pair, context, and triple binding                                           | `code_stronger_than_source` |       0.98 |
| `TRI-07` | `triples/generation.rs:789-820` checks received private `a_i` and `b_i` evaluations against `E(z_i)` and `F(z_i)`                                  | `presign/src/triples.rs:660-686` enforces both equations at fixed recipient coordinate 2 or 3                                             | `full_match`                |       0.99 |
| `TRI-08` | `triples/generation.rs:821-881` verifies `C_i = e_i(0)F(0)` using DLogEq                                                                           | `presign/src/triples/finalize.rs` uses the same relation and rejects an identity alternate generator                                      | `code_stronger_than_source` |       0.98 |
| `TRI-09` | `triples/generation.rs:366-432,959-997` verifies knowledge of each committed multiplication output                                                 | `presign/src/triples/finalize.rs` verifies a `ProductShare` DLog proof before aggregation                                                 | `full_match`                |       0.98 |
| `TRI-10` | `triples/generation.rs:436-444,1000-1011` requires the final public sharing polynomial to satisfy `L(0) = C`                                       | `presign/src/triples/finalize.rs:477-548` enforces the terminal public product equation before output                                     | `full_match`                |       0.98 |
| `TRI-11` | `triples/generation.rs:446-458,1014-1039` requires `c_iG = L(z_i)`                                                                                 | Finalization verifies the recipient-private product share equation before constructing opaque `ValidatedTriple` values                    | `full_match`                |       0.99 |

## Presign, rerandomization, online signing, and one-use checks

| ID       | Pinned source evidence                                                                                                             | Purpose-built owner and disposition                                                                                                     | Classification              | Confidence |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ---------: |
| `PRE-01` | `presign.rs:25-57` validates participant count, threshold, duplicate participants, self membership, and matching triple thresholds | Separate fixed-role inputs eliminate participant and threshold parameters                                                               | `code_stronger_than_source` |       1.00 |
| `PRE-02` | `presign.rs:38-40` explicitly omits a triple participant-set check                                                                 | `presign/src/lib.rs:224-278` requires both opaque triples to carry one exact context and public key                                     | `code_stronger_than_source` |       1.00 |
| `PRE-03` | `presign.rs:114-119` rejects a zero peer `e` share                                                                                 | `presign/src/lib.rs:447-456` rejects zero peer shares before reconstruction                                                             | `full_match`                |       1.00 |
| `PRE-04` | `presign.rs:125-131` requires reconstructed `eG = E`                                                                               | `presign/src/lib.rs:458-461` enforces the same equation                                                                                 | `full_match`                |       1.00 |
| `PRE-05` | `presign.rs:159-168` requires `alpha G = K + A` and `beta G = X + B`                                                               | `presign/src/lib.rs:491-505` enforces both equations before output                                                                      | `full_match`                |       1.00 |
| `PRE-06` | `presign.rs:170-175` rejects failed `e` inversion                                                                                  | `presign/src/lib.rs:507-510` returns `NonInvertibleE`; one-use adapters burn the pair                                                   | `full_match`                |       1.00 |
| `RER-01` | `ot_based_ecdsa/mod.rs:63-69` requires stored `R` to equal the rerandomization argument                                            | `online/src/lib.rs` constructs both role-local committed materials from one exact pair record and checks all public bindings            | `code_stronger_than_source` |       0.98 |
| `RER-02` | `ecdsa/mod.rs:139-187` derives a canonical non-zero HKDF-SHA3-256 scalar                                                           | `online/src/lib.rs:325-381` freezes the production transcript and canonical retry behavior                                              | `full_match`                |       0.96 |
| `RER-03` | `ecdsa/mod.rs:89-103` requires 32 fresh, public, unpredictable entropy bytes                                                       | Client commits a fresh contribution in prepare; SigningWorker then samples and reveals its contribution; finalize opens the Client commitment; XOR supplies the HKDF entropy | `code_stronger_than_source` |       0.97 |
| `RER-04` | `ecdsa/mod.rs:150-185` increments a one-byte retry counter without checked overflow                                                | The local derivation performs at most 256 attempts and returns a typed terminal error                                                   | `code_stronger_than_source` |       1.00 |
| `RER-05` | `ot_based_ecdsa/mod.rs:70-82` checks non-zero `delta`, then unwraps its inverse                                                    | The local derivation retains a checked non-zero scalar and propagates inversion failure                                                 | `code_stronger_than_source` |       0.99 |
| `SIG-01` | `sign.rs:16-20` warns that arbitrary scalar signing is dangerous                                                                   | Router authorization supplies one exact 32-byte EVM digest before committed use; online crates accept fixed digest bytes                | `code_stronger_than_source` |       0.96 |
| `SIG-02` | `sign.rs:136-157` computes `s_i = h*k'_i + r*sigma'_i` with Lagrange weighting                                                     | `online/src/lib.rs:249-266` preserves the role-local share equation after fixed rerandomization                                         | `full_match`                |       0.98 |
| `SIG-03` | `sign.rs:117-120` performs low-`s` normalization                                                                                   | `online/src/lib.rs:267-323` uses conditional selection before final verification                                                        | `full_match`                |       0.99 |
| `SIG-04` | `ecdsa/mod.rs:63-79` rejects zero `r`, zero `s`, high `s`, and a failed verification equation                                      | The SigningWorker finalizer constructs canonical scalars, enforces low-`s`, and verifies against the registered key                     | `full_match`                |       0.98 |
| `SIG-05` | The pinned signer returns a verified signature; recovery binding is required by the Router A/B product contract                    | The finalizer derives the recovery ID only when it recovers the registered key for the exact digest                                     | `code_stronger_than_source` |       0.96 |
| `USE-01` | `presign.rs:13-19` states that a presignature must never be reused                                                                 | `pool/src/lib.rs:183-470` permits only `available -> reserved -> committed -> tombstone`; success and every uncertain exit are terminal | `code_stronger_than_source` |       1.00 |

## Abort composition

| ID       | Pinned source evidence                                                                                                         | Purpose-built owner and disposition                                                                                               | Classification              | Confidence |
| -------- | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ---------: |
| `ABT-01` | Reachable `?` and explicit `Err` sites in the pinned rows terminate the NEAR future                                            | Each fixed transition returns one typed error and consumes its state; adapters reconcile and tombstone the matching pair          | `full_match`                |       0.97 |
| `ABT-02` | `protocol/internal.rs:241-255` and `protocol/helpers.rs:19-24` can wait indefinitely for absent messages                       | Authenticated request deadlines cause terminal timeout and pair destruction                                                       | `code_stronger_than_source` |       0.95 |
| `ABT-03` | `triples/generation.rs:567-575,721-787,854-884,971-1039` and `triples/mta.rs:66-70,96-119` contain vector indexing assumptions | Fixed arrays and exact frame sizes prevent malformed vector lengths from reaching indexing; parser failures are controlled aborts | `code_stronger_than_source` |       0.99 |

## Deliberate divergence and open assumptions

`OT-06` is the sole known behavioral mismatch in the selected cryptographic
call graph. Reproducing its bytes would make the random-OT expanded rows
independent of their base keys. The production construction therefore follows
the corrected keyed expansion specified in
[`random-ot-extension-v1.md`](./random-ot-extension-v1.md). Exact upstream
extension-byte parity is forbidden.

The inventory establishes source-to-target check ownership. It does not prove
the active security of the corrected OT/MTA composition. `A-OT-CORRECTED` in
[`assurance-ledger-v1.md`](./assurance-ledger-v1.md) remains an independent
review gate. Transport deadlines, authenticated delivery, atomic persistence,
and independent-account non-collusion retain their deployment and operational
assumptions.

The machine guard in the oracle crate verifies the complete required ID set,
the absence of placeholder rows, the pinned source tree, and every cited
source-file digest. Changes to the fixed-path call graph require a reviewed
inventory and oracle-manifest update.

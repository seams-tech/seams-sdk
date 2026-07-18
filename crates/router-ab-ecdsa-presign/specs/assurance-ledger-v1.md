# Fixed 2-of-2 ECDSA assurance ledger v1

Status: normative local construction and assumption ledger. This document
defines the construction implemented by `router-ab-ecdsa-presign`,
`router-ab-ecdsa-online`, and `router-ab-ecdsa-pool`. Independent design review
remains the production-promotion gate.

## Scope and source corpus

The normative local corpus is:

- [`fixed-driver-v1.md`](./fixed-driver-v1.md): fixed eleven-round state
  machine, roles, messages, and output;
- [`polynomial-commitments-v1.md`](./polynomial-commitments-v1.md): committed
  degree-one/degree-one/degree-zero polynomial shape;
- [`proof-kernel-v1.md`](./proof-kernel-v1.md): role-, context-, and
  triple-bound DLog and DLogEq proofs;
- [`base-rot-v1.md`](./base-rot-v1.md): fixed 128-instance base random OT;
- [`random-ot-extension-v1.md`](./random-ot-extension-v1.md): corrected
  768-of-1024 malicious random-OT extension;
- [`fixed-mta-v1.md`](./fixed-mta-v1.md): two fixed 384-OT MTA instances;
- [`committed-triple-finalization-v1.md`](./committed-triple-finalization-v1.md):
  proof-checked two-triple finalization;
- [`prototype-security.md`](./prototype-security.md): claim boundary and the
  critical upstream OT-expansion divergence;
- [`upstream-check-inventory.md`](./upstream-check-inventory.md): pinned
  source-to-target ownership for every fixed-path security check family;
- [`abort-corpus-v1.md`](./abort-corpus-v1.md): executable malformed-message,
  wrong-binding, reflection, replay/order, cryptographic-failure, and one-use
  terminal evidence; and
- [`online-lifecycle-v1.md`](../../router-ab-ecdsa-online/specs/online-lifecycle-v1.md):
  one-use online equations, low-`s`, recovery, and verification.

The exact upstream oracle is commit
`db609be5021eb9d794f577601f422818fbdfe246`, Git tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`. The machine-checked source and
vector manifest is
[`fixtures/v1/manifest.json`](../../router-ab-ecdsa-near-oracle-tests/fixtures/v1/manifest.json),
SHA-256 `0e38983aebc110b4f0407a6b2d0349b3e398b373e0639472e1510e47113fc577`.
It pins 23 upstream source/document files by digest and seven deterministic
vector families. `oracle_manifest.rs` verifies the Cargo git source, commit,
tree, every file digest, and the exact vector-ID set. The presign replay vector
freezes all four role-pair cases under normalized semantic trace digest
`2d6d2691b277b65ebd66fe81d66d0c875412747265d18c7131963f1b8ab72d06`.

## Fixed construction

The group is secp256k1 with generator `G` and scalar order `q`. There are two
compile-time roles:

| Role          | Participant ID | Interpolation coordinate | Lagrange coefficient |
| ------------- | -------------: | -----------------------: | -------------------: |
| Client        |            `1` |                      `2` |                  `3` |
| SigningWorker |            `2` |                      `3` |           `-2 mod q` |

Router A/B derivation supplies additive shares `d_C + d_S = x mod q` and the
authenticated group key `X = xG`. The presign API accepts role-local additive
shares. Runtime participant vectors, thresholds, coordinates, role selectors,
and protocol negotiation are absent.

For each triple index `j in {0, 1}`, each role commits to fixed polynomial
shares, proves the required DLog/DLogEq relations, completes the corrected
malicious OT/MTA stack, and emits an opaque `ValidatedTriple` only after the
public product and recipient-private share equations pass. The two validated
triples drive presigning:

```text
k'_i     = lambda_i * k_i
e'_i     = lambda_i * e_i
a'_i     = lambda_i * a_i
b'_i     = lambda_i * b_i
x'_i     = lambda_i * x_i
e        = sum_i e'_i
alpha_i  = k'_i + a'_i
beta_i   = x'_i + b'_i
alpha    = sum_i alpha_i
beta     = sum_i beta_i
R        = e^-1 * D
sigma_i  = alpha * x_i - beta * a_i + c_i
```

Both roles verify `eG = E`, `alpha G = K + A`, and `beta G = X + B` before
emitting `(R, k_i, sigma_i)`. Online signing derives the shared non-zero
rerandomizer from the Client-commit/SigningWorker-reveal public coin and the
fixed HKDF-SHA3-256 transcript, commits one exact
presignature use, computes the Client share, combines it at the SigningWorker,
normalizes low-`s`, verifies the final signature, and derives the recovery ID
against the registered group key.

The Client samples uniform `c_C <- {0,1}^256` and sends
`H("router-ab-ecdsa-derivation/client-rerandomization-commitment/v1" || c_C)`
in prepare. After admitting and binding that request, the SigningWorker samples
and persists uniform `c_W <- {0,1}^256`, then reveals `c_W` in its prepare
response. Finalize opens `c_C`; the SigningWorker reconstructs the prepare
digest and burns the pair on any mismatch before reading committed presign
material. Both roles pass `c_C XOR c_W` to the existing context-bound HKDF.
The coin is unpredictable when either role is honest. Selective abort affects
availability, which is outside the claim boundary.

The canonical wire has eleven directional rounds, fixed role and round tags,
strict lengths, a maximum frame of 49,228 bytes, and 152,826 aggregate bytes.
The frozen 22-frame corpus digest is
`16bdcb259e861750250969bb4b9491f4620f0157cdda9a0a4433e6f2b9ed6eac`.

## Adversary and trust model

The cryptographic protocol targets active security against one corrupt role.
At least one of Client or SigningWorker remains honest, retains its additive
share and fresh randomness, and follows the one-use state machine. A malicious
peer may send malformed, reordered, reflected, substituted, replayed, or
inconsistent messages and may abort at any point.

The expected result is either a verified signature or a terminal abort that
burns both pair halves. The construction provides no fairness or availability
claim. A peer can always stop progress. Output delivery after local commit is
intentionally ambiguous; recovery burns the committed pair.

Authenticated Router A/B transport supplies role identity, confidentiality,
integrity, replay protection, and exact session/scope binding. The protocol
does not derive security from network secrecy alone. Deriver A and Deriver B
are absent from normal signing after activation.

Independent Cloudflare accounts are the production operational model. They
reduce correlated administrative compromise and preserve the deployment's
non-collusion assumption. Same-account deployment is a development profile;
one administrator can compromise both roles, so it carries no operational
one-honest-role claim. The wire, cryptographic equations, and browser artifact
boundary remain identical in both profiles.

## Spec-to-code alignment

| ID                 | Spec excerpt and source                                                                                                                        | Code evidence                                                                                                                                                                         | Classification            | Confidence | Evidence                                                                                                       |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ---------: | -------------------------------------------------------------------------------------------------------------- |
| `ALG-01`           | “exactly two roles” and fixed coordinates/coefficients, [`fixed-driver-v1.md`](./fixed-driver-v1.md)                                           | Separate Client/SigningWorker session and state types; fixed constants in [`lib.rs`](../src/lib.rs#L60) and [`session.rs`](../src/session.rs#L163)                                    | `full_match`              |     `1.00` | compile-fail generic topology and cross-role fixtures                                                          |
| `BND-01`           | canonical scalar and compressed non-identity point boundaries, [`prototype-security.md`](./prototype-security.md)                              | `AdditiveKeyShare::from_bytes`, point/scalar parsers in [`lib.rs`](../src/lib.rs#L206) and online material parsers in [`online/lib.rs`](../../router-ab-ecdsa-online/src/lib.rs#L150) | `full_match`              |     `0.99` | boundary unit tests and malformed Wasm inputs                                                                  |
| `CTX-01`           | every phase binds scope, pair, role, and triple index, all layer specs                                                                         | pair derivation in [`session.rs`](../src/session.rs#L113); typed proof contexts in [`proofs.rs`](../src/proofs.rs#L254); fixed codec tags in [`codec.rs`](../src/codec.rs#L65)        | `code_stronger_than_spec` |     `0.97` | context-substitution and role-reflection tests                                                                 |
| `POLY-01`          | degree-one `E/F`, degree-zero `L`, committed opening and private evaluations, [`polynomial-commitments-v1.md`](./polynomial-commitments-v1.md) | commit/open/private-share pipeline in [`triples.rs`](../src/triples.rs#L387) and [`triples.rs`](../src/triples.rs#L488)                                                               | `full_match`              |     `0.98` | frozen polynomial vector; altered opening/share aborts                                                         |
| `PRF-01`           | role/triple/context-bound Schnorr and Chaum-Pedersen proofs, [`proof-kernel-v1.md`](./proof-kernel-v1.md)                                      | fixed proof entry points in [`proofs.rs`](../src/proofs.rs#L254) through line 338                                                                                                     | `code_stronger_than_spec` |     `0.97` | role reflection, wrong context, tampered response, zero nonce/witness tests                                    |
| `ROT-01`           | 128 fixed base OTs and non-identity peer points, [`base-rot-v1.md`](./base-rot-v1.md)                                                          | fixed arrays and role-local start/receive functions in [`base_rot.rs`](../src/triples/base_rot.rs#L188)                                                                               | `full_match`              |     `0.97` | frozen base-ROT vector and degenerate-point aborts                                                             |
| `EXT-UPSTREAM-01`  | pinned upstream random-OT row expansion is the behavioral source, [`prototype-security.md`](./prototype-security.md)                           | local keyed expansion in [`extension.rs`](../src/triples/base_rot/extension.rs#L895) deliberately produces different bytes                                                            | `mismatch`                |     `1.00` | critical upstream key-insensitivity regression; exact upstream extension-byte parity is forbidden              |
| `EXT-LOCAL-01`     | keyed 768-of-1024 malicious random-OT extension, [`random-ot-extension-v1.md`](./random-ot-extension-v1.md)                                    | fixed counts and keyed expansion in [`extension.rs`](../src/triples/base_rot/extension.rs#L23) and [`extension.rs`](../src/triples/base_rot/extension.rs#L895)                        | `full_match`              |     `0.95` | every-base-key sensitivity and all-128-equation consistency tests; independent composition review remains open |
| `MTA-01`           | two 384-OT MTA instances, [`fixed-mta-v1.md`](./fixed-mta-v1.md)                                                                               | fixed counts and sender/receiver flows in [`mta.rs`](../src/triples/base_rot/extension/mta.rs#L22) and [`mta.rs`](../src/triples/base_rot/extension/mta.rs#L326)                      | `full_match`              |     `0.96` | frozen MTA vector; altered/noncanonical ciphertext aborts                                                      |
| `TRI-01`           | two proof-checked multiplication triples, [`committed-triple-finalization-v1.md`](./committed-triple-finalization-v1.md)                       | terminal equations and opaque output in [`finalize.rs`](../src/triples/finalize.rs#L477) through line 548                                                                             | `full_match`              |     `0.96` | corrupted MTA and private/public equation tests                                                                |
| `PRE-01`           | `eG`, `alpha G`, `beta G` checks and fixed presign equations, [`fixed-driver-v1.md`](./fixed-driver-v1.md)                                     | consuming role states in [`lib.rs`](../src/lib.rs#L356) through line 416 and eleven-round driver                                                                                      | `full_match`              |     `0.98` | complete new/new driver, cross-Wasm completion, tampered-alpha abort                                           |
| `WIRE-01`          | strict bounded canonical frames and fixed numeric registry, [`fixed-driver-v1.md`](./fixed-driver-v1.md)                                       | one-pass frame parser in [`codec.rs`](../src/codec.rs#L165)                                                                                                                           | `code_stronger_than_spec` |     `0.99` | 22-frame digest, exhaustive truncations/header mutations, 4,096 seeded mutations                               |
| `ONL-01`           | one-use Client share and SigningWorker combination, [`online-lifecycle-v1.md`](../../router-ab-ecdsa-online/specs/online-lifecycle-v1.md)      | committed-only APIs in [`online/lib.rs`](../../router-ab-ecdsa-online/src/lib.rs#L249) and line 267                                                                                   | `full_match`              |     `0.99` | NEAR parity, compile-fail ordering/reuse, final signature vector                                               |
| `RER-01`           | fixed HKDF-SHA3-256 non-zero rerandomizer, same online spec                                                                                    | [`derive_rerandomization_delta`](../../router-ab-ecdsa-online/src/lib.rs#L325)                                                                                                        | `full_match`              |     `0.95` | frozen online vector; checked retry overflow and non-zero result                                               |
| `RER-COIN-01`      | either honest online role makes the rerandomizer seed unpredictable, same online spec                                                          | domain-separated Client commitment in `router-ab-core`; post-admission SigningWorker contribution in `router-ab-cloudflare`; XOR in [`online/lib.rs`](../../router-ab-ecdsa-online/src/lib.rs)                                                        | `full_match`              |     `0.98` | frozen Rust/TypeScript commitment vector, opening substitution, both-contribution influence, and terminal binding-rejection tests |
| `SIG-01`           | low-`s`, verification, and recovery to the registered key, same online spec                                                                    | conditional low-`s`, verify, and recovery in [`online/lib.rs`](../../router-ab-ecdsa-online/src/lib.rs#L267) through line 323                                                         | `full_match`              |     `0.98` | altered share/key/`R` rejection and recoverable-signature parity                                               |
| `USE-01`           | every pair is monotonic and terminal after use or uncertainty, refactor lifecycle invariants                                                   | reserve/commit/destroy/recovery/retirement in [`pool/lib.rs`](../../router-ab-ecdsa-pool/src/lib.rs#L218) through line 465                                                            | `code_stronger_than_spec` |     `0.99` | stale-CAS, timeout, abort, crash, ambiguous delivery, retirement, duplicate-use tests                          |
| `DEP-01`           | oracle and generic threshold backend stay outside production                                                                                   | default modules are private/test-feature gated; fixed leaf graphs exclude forbidden dependencies                                                                                      | `full_match`              |     `1.00` | six production-boundary tests and exact Wasm export guards                                                    |
| `ORACLE-REPLAY-01` | four-case semantic replay across the pinned and production transcript profiles                                                                 | NEAR/NEAR, purpose-built/purpose-built, purpose-built Client against the NEAR SigningWorker trace, and purpose-built SigningWorker against the NEAR Client trace                      | `full_match`              |     `1.00` | three executable parity tests and frozen normalized trace digest                                               |
| `CT-01`            | fixed public loops and no secret division/remainder, layer specs                                                                               | release ARM64 and Wasm scans plus source review                                                                                                                                       | `partial_match`           |     `0.85` | zero division/sqrt errors; branch-dataflow and runtime assumptions remain open                                 |

## Product-behavior cutover matrix

| Behavior | Preserved relation | Executable checkpoint |
| --- | --- | --- |
| Public key and address | Role-local public shares sum to the same registered group key and Ethereum address | `role_local_mvp`, `native_readiness_vectors`, and the 44-test EVM-family identity suite |
| Online signature | Client share and final signature match the pinned oracle; finalization verifies the registered key | `purpose_built_online_roles_match_pinned_near_oracle` and `generated_presign_fixture_matches_oracle_finalization` |
| Canonical signature encoding | Final `s` is low, the signature verifies, and recovery selects the registered group key | `SIG-01`, online parity, and altered-share/key/`R` rejection tests |
| Signing budgets | Exact Wallet Session grant and key-slot authority remain bound through refresh | `thresholdEcdsa.walletBudgetRefresh.unit.test.ts` |
| Recovery and explicit export | Ready, refreshed, page-reloaded, and Email OTP export paths retain verified public facts and reconstruct the registered key only after authorization | `ecdsaExportMaterial.unit.test.ts`, `native_readiness_vectors`, and role-local export reconstruction tests |
| Bootstrap persistence | Passkey and Email OTP activation persist the same canonical EVM-family identity without legacy projection rows | `thresholdEcdsa.bootstrapPersistence.unit.test.ts` |

The focused product checkpoint passes 62 browser-side identity, budget,
bootstrap, and export tests plus the native online/oracle and role-local
derivation suites. These checks establish behavior preservation for the local
cutover. Deployed performance and operational acceptance remain in the
deployment plan.

### Deliberate divergence `EXT-UPSTREAM-01`

The pinned upstream `triples/bits.rs` row expansion updates one hasher and
finalizes a different unkeyed clone. Expanded rows therefore ignore each
base-OT key. Exact upstream extension-byte parity is forbidden. The local
construction uses keyed expansion and verifies all 128 consistency equations
before output. This is a critical upstream divergence with confidence `1.00`.
Security review must evaluate the corrected local construction directly.

## Assumption ledger

| ID                     | Assumption                                                                                                                                   | Status                         | Evidence or required closure                                                                      |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------- |
| `A-SECP`               | `k256` implements secp256k1 scalar/group arithmetic and constant-time secret operations used here                                            | accepted dependency assumption | pinned dependency; source/native/Wasm inspection covers local composition                         |
| `A-HASH`               | SHA-256, SHA3-256, HMAC, and HKDF provide their standard collision/PRF/KDF properties                                                        | accepted dependency assumption | fixed domains and vectors; no local primitive implementation                                      |
| `A-RNG`                | each role receives independent cryptographically secure randomness and does not reuse protocol coins                                         | operational assumption         | production uses `OsRng`; deterministic providers remain test-only by dependency guard             |
| `A-COIN-COMMIT`        | SHA-256 is binding for the domain-separated commitment and hides a uniformly random 256-bit Client contribution until opening                | accepted primitive assumption  | frozen Rust/TypeScript vector; prepare digest binds the commitment; opening substitution burns     |
| `A-CHANNEL`            | Router A/B service transport authenticates role, scope, session, order, and payload and provides confidentiality/integrity/replay protection | deployment assumption          | enforced by Router A/B routes and deployment plan; full transport proof is outside these crates   |
| `A-ONE-HONEST`         | at least one Client/SigningWorker role and its administrative account remain uncompromised                                                   | production trust assumption    | independent-account deployment; same-account development has no such operational claim            |
| `A-OT-CORRECTED`       | the keyed 128-bit base OT plus corrected malicious extension/MTA composition realizes the required active-security functionality             | review required                | local equations/tests/specs exist; independent construction review remains mandatory              |
| `A-ONEUSE`             | Client IndexedDB and SigningWorker Durable Object transitions persist atomically before output                                               | locally evidenced              | shared reducer, encrypted Client adapter, Cloudflare/local persistence tests, fault matrix        |
| `A-CT-BRANCH-DATAFLOW` | compiled branches depend only on public framing/state or aggregate protocol validity                                                         | open                           | heuristic scans report branches without dataflow; independent review or stronger tooling required |
| `A-CT-RUNTIME`         | JavaScript/Wasm engines and Cloudflare Workers do not introduce exploitable runtime timing channels                                          | unclaimed                      | static inspection cannot establish this property                                                  |
| `A-ORACLE`             | behavioral parity vectors correctly represent the pinned source                                                                              | locally evidenced              | commit/tree/file digests and vector IDs are machine checked; parity makes no security-proof claim |

## Party views and outputs

The Client view contains its additive key share, local protocol randomness,
local triple/presign shares, authenticated peer messages, public group key,
scope/pair bindings, signing digest, its hidden Client coin contribution, the
revealed SigningWorker contribution, and its final signature share. The
SigningWorker view contains the symmetric role-local values plus the Client
commitment, its own contribution, the later Client opening and signature share,
and the final signature. Neither
view contains the peer additive key share. Deriver A/B root-share material is
outside both normal-signing views.

Only the SigningWorker releases the verified recoverable signature. Every
error after reservation destroys or terminally tombstones the exact pair.
Errors contain stable classes and public context; secret scalars, OT keys,
proof witnesses, shares, and decrypted presign material are neither formatted
nor logged.

## Remaining promotion gates

1. Obtain independent review of `A-OT-CORRECTED`, the upstream check inventory,
   transcript separation, and the one-corrupt-role composition.
2. Classify or retain `A-CT-BRANCH-DATAFLOW` and `A-CT-RUNTIME` as explicit
   non-claims.
3. Run deployed Cloudflare performance and operational acceptance under the
   independent-account profile. Deployment evidence belongs to the deployment
   plan and does not change this cryptographic ledger.

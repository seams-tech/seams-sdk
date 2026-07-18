# Router A/B ECDSA bounded cryptographic review

Status: **APPROVED — supersedes the earlier RAR-01 rejection**

This record is the superseding independent review receipt for the purpose-built
fixed 2-of-2 ECDSA construction. The reviewed presign equations, corrected
random-OT extension, MTA/triple composition, public-coin rerandomization,
one-use lifecycle, oracle boundary, and fixed-role APIs are internally
consistent. `RAR-01` is resolved by the reviewed one-sided commit/reveal
construction.

Current-tree scope note: this approval remains the receipt for the exact
digest-pinned construction snapshot below. Those immutable corpus documents
retain their reviewed bytes. Their Cloudflare-adapter completeness statements
are superseded for the newer integration by the separately `REJECTED` review at
`docs/evidence/refactor-89/cloudflare-signing-lifecycle-security-review-v1.md`.

## Review identity

- Reviewer: Codex independent cryptographic review agent
- Affiliation: OpenAI Codex
- Review date: 2026-07-17
- Base Git commit: `186e55d99f0a1df0f0229b44e6ceaf3aec00f013`
- Reviewed source tree: 122-file SHA-256 manifest rooted at
  `68a9981a189c8b88acc6eec9d970e16bb864f2bfb4289815d2f82aa32460985e`
- Decision: `APPROVED`
- Receipt authentication: recorded by the named agent in the originating Codex
  review task; no detached cryptographic signature was produced

The reviewer did not author the normative construction artifacts or implement
the fixed presign/online kernels.

## Digest-pinned review corpus

All listed corpus digests were recomputed from the reviewed working tree and
matched exactly.

| Artifact | SHA-256 | Review purpose |
| --- | --- | --- |
| `crates/router-ab-ecdsa-presign/specs/assurance-ledger-v1.md` | `9cb381cbf9decdd687cfbe3ab6b28b223c484d8877185f228bd1abec681ceda8` | Construction, adversary model, party views, equations, assumptions, claims, and deliberate divergence |
| `crates/router-ab-ecdsa-presign/specs/fixed-driver-v1.md` | `8f9fa720bc39b60adc37f1a86aaff176c4bd5f130abfbd6796941461b97d9222` | Fixed rounds, transcript framing, bounds, state transitions, adapters, and mutation coverage |
| `crates/router-ab-ecdsa-presign/specs/polynomial-commitments-v1.md` | `17a43dec29e61752c91ff0516c8a52ab6efecee48ae2a5d61ceaad1173a30fa0` | Fixed committed-polynomial shape, transcript, and share equations |
| `crates/router-ab-ecdsa-presign/specs/proof-kernel-v1.md` | `bbc8d79b4c072d7c9e8128c30d38cbc5cc21d00213fb2e8cb60e32509136816b` | DLog/DLogEq statements, transcripts, randomness, and proof API boundary |
| `crates/router-ab-ecdsa-presign/specs/base-rot-v1.md` | `bf5a5d5bea4e843d3cc725bf1f60a8e7569a8d743b3ad7272b24adc0e22de59e` | Fixed base random-OT equations, bindings, and sealed-state boundary |
| `crates/router-ab-ecdsa-presign/specs/random-ot-extension-v1.md` | `4e52cb2c7503d98d577363d5ba8fc3f7d241631de23021f93ab0bcc954105b80` | Corrected malicious random-OT extension and deliberate upstream divergence |
| `crates/router-ab-ecdsa-presign/specs/fixed-mta-v1.md` | `81d866ef2bdf05b14b1861deb79e821b64f3830f0a86a1225239e99782bea74c` | Fixed MTA equations, role schedule, and malicious-behavior boundary |
| `crates/router-ab-ecdsa-presign/specs/committed-triple-finalization-v1.md` | `45defbe4eab65a61cecb6981aa9640a9accb35ced836bc74e45ce0907dab30a6` | Product/share proof composition and terminal triple checks |
| `crates/router-ab-ecdsa-presign/specs/prototype-security.md` | `6f08665b1bac22e3f5f0c50c1d3c4dec6ea1f1bbdd2b038393d22fbfa4159ca2` | Incremental construction record and bounded claim history |
| `crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md` | `7de84596087ffd4b69c4f140d9a856f5dde72091441d0c064362d846467aa7e0` | Online equations, public coin, low-s/recovery, one-use composition, and adapter boundary |
| `crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md` | `1fa79931d6bbd056384b75f62abf4397485af471c42921d346efc8c968e83f93` | Persistent lifecycle, CAS, burn, recovery, and output-release invariants |
| `crates/router-ab-ecdsa-presign/specs/upstream-check-inventory.md` | `99b5bf4b967be2ea5bebfed4aaa9ac7b09f962b7ca3016337136b46e0c31a5f2` | Forty-seven upstream checks and dispositions |
| `crates/router-ab-ecdsa-presign/specs/abort-corpus-v1.md` | `8c18537bb548740cc667039bce5f315b755b9a68634ba9760f98c17fc974d87f` | Critical malformed, replay, binding, proof, OT/MTA, online, and one-use failures |
| `crates/router-ab-ecdsa-near-oracle-tests/fixtures/v1/manifest.json` | `0e38983aebc110b4f0407a6b2d0349b3e398b373e0639472e1510e47113fc577` | Pinned NEAR source, oracle corpus, semantic replay, and provenance |
| `docs/evidence/refactor-89/phase-d-bounded-assurance-v1.json` | `5b86075079103e05b6a79e60469b732f2f0080e5995426e0e02d8f91bcd500fb` | Machine-readable bounded assurance evidence |
| `docs/evidence/refactor-89/phase-e-local-artifacts-v1.json` | `cc639cbcdf0703dd2bffda44ea771fef70ec8d0feccf15a82d9b8784887ee79e` | Final local artifacts, deletion audit, builds, and lifecycle checks |

Any change to a corpus artifact or reviewed-manifest file invalidates this
decision receipt and requires a new independent review.

The later registration-client package split changed packaging, generated
assets, and two manifest-listed boundary guards while preserving every
cryptographic corpus digest above. The independent
[registration package delta review](../evidence/refactor-89/registration-package-delta-review-v1.md)
finds the package split sound in isolation. It rejects a whole-tree
packaging-only classification because three separately changed
`router-ab-cloudflare` manifest files contain signing/pool lifecycle behavior.
Those files require bounded review or restoration before this receipt can
identify the current complete tree. The original construction claim and
122-file manifest remain historical evidence for their exact reviewed bytes.

The remediation evidence receipt
`docs/evidence/refactor-89/rar-01-public-coin-remediation-v1.md` has SHA-256
`b020ed1b9944a7064fcf4ff487d92eddc480ddd50d523bb8a02aebdf726f5e0e`.
The reviewed online Wasm and emitted browser worker have SHA-256
`05f441332aa7c410207e3df2fb8d1d73e1c874d351af9e92ac106655a2dab657`
and `25c2cb8601e9835a44752821bb9ad610a751de737508af5bc20005cf4a41fcce`.

## Adversary model and claim boundary

The claimed setting is secp256k1 fixed 2-of-2 signing with Client participant ID
1 at coordinate 2 and SigningWorker participant ID 2 at coordinate 3. Their
Lagrange coefficients are `lambda_C = 3` and `lambda_W = -2`. The adversary may
actively corrupt either role, send malformed or replayed messages, adapt messages
to prior transcript data, or abort. The honest role retains its additive key
share, fresh local randomness, and one-use persistence. Authenticated private
transport, secure RNGs, secp256k1 hardness, `A-OT-CORRECTED`,
`A-COIN-COMMIT`, and independent operational control of the two roles are
assumptions. `A-COIN-COMMIT` requires the domain-separated SHA-256 commitment to
be binding and to hide a uniform 256-bit Client contribution until opening.
Fairness, availability, runtime constant-time behavior, and security after both
roles are corrupted are excluded claims.

The review treated diagnostics, compatibility vectors, and source guards as
evidence. None of them supplied an adversarial-security proof by themselves.

## Spec-IR

```yaml
spec_ir:
  - id: SPEC-001
    source: assurance-ledger-v1.md:58-80
    statement: Fixed roles map additive shares d_C+d_W=x into local private inputs x_i=d_i/lambda_i and require the three terminal presign commitment equations.
    preconditions: [canonical nonzero group key, canonical additive shares, exact pair context, two validated triples]
    postconditions: [eG=E, alphaG=K+A, betaG=X+B, role-local presign output]
    confidence: 0.99
  - id: SPEC-002
    source: fixed-driver-v1.md:20-92
    statement: The protocol has eleven fixed rounds, twenty-two total frames, bounded frame sizes, and role-specific consuming transitions.
    preconditions: [authenticated ordered delivery, exact protocol ID]
    postconditions: [completed pair or typed terminal abort]
    confidence: 0.99
  - id: SPEC-003
    source: polynomial-commitments-v1.md:18-70
    statement: Each role commits degree-one E and F polynomials plus one product-sharing slope and proves recipient evaluations against the commitments.
    preconditions: [fresh nonzero coefficients, bound scope and pair]
    postconditions: [verified peer-private E/F evaluations]
    confidence: 0.98
  - id: SPEC-004
    source: proof-kernel-v1.md:13-77
    statement: Schnorr DLog and Chaum-Pedersen DLogEq proofs bind suite, domain, scope, pair, role, triple, proof kind, statement, and retry counter.
    preconditions: [canonical nonidentity statements, fresh nonzero prover nonce]
    postconditions: [verified witness relation or abort]
    confidence: 0.99
  - id: SPEC-005
    source: base-rot-v1.md:15-72
    statement: Exactly 128 base random OTs derive role-, branch-, index-, and context-bound keys while sealed outputs hide the unselected branch or receiver choices.
    preconditions: [valid points, fresh sender and receiver scalars]
    postconditions: [correlated base keys for one fixed role direction]
    confidence: 0.97
  - id: SPEC-006
    source: random-ot-extension-v1.md:15-112
    statement: Corrected keyed row expansion produces 768 released OTs from 1024 padded rows and authenticates correlation with a post-correlation challenge over all 128 columns.
    preconditions: [A-OT-CORRECTED, authenticated transport, valid base ROT]
    postconditions: [sender and receiver random-OT outputs or abort before receiver release]
    confidence: 0.95
  - id: SPEC-007
    source: fixed-mta-v1.md:13-105
    statement: Two 384-OT MTA instances per direction yield additive cross-product shares; fixed Triple 0/1 scheduling prevents runtime role or index selection.
    preconditions: [disjoint verified random OTs, canonical scalar inputs]
    postconditions: [sealed multiplication shares whose sum supplies both cross terms]
    confidence: 0.96
  - id: SPEC-008
    source: committed-triple-finalization-v1.md:13-77
    statement: DLog, DLogEq, public product, and recipient-private c-share checks precede construction of each opaque ValidatedTriple.
    preconditions: [verified polynomial shares, sealed MTA outputs, proof-bound contributions]
    postconditions: [c=a*b for reconstructed shares, opaque validated triples]
    confidence: 0.98
  - id: SPEC-009
    source: online-lifecycle-v1.md:13-101
    statement: A commit/reveal public coin supplies both roles with one canonical nonzero HKDF-SHA3 rerandomizer; weighted signature shares, low-s normalization, registered-key verification, and recovery binding remain unchanged.
    preconditions: [uniform hidden contribution from either honest role, binding Client commitment, matching R, one committed presign pair]
    postconditions: [verified 65-byte recoverable signature or terminal failure]
    confidence: 0.98
  - id: SPEC-010
    source: persistent-pool-lifecycle-v1.md:13-73
    statement: Available, reserved, committed, and tombstone form a forward-only CAS lifecycle; timeout, crash, ambiguity, substitution, and retirement destroy material.
    preconditions: [durable atomic record replacement, exact scope/pair/revision]
    postconditions: [at-most-once material release and absorbing terminal state]
    confidence: 0.98
  - id: SPEC-011
    source: online-lifecycle-v1.md:44-71; upstream-check-inventory.md:67-87
    statement: Client commits SHA-256(domain || C) in prepare, SigningWorker samples and durably reveals W after admission, Client opens C in finalize, and C XOR W feeds the context-bound HKDF.
    preconditions: [one role may be actively corrupt]
    postconditions: [the corrupt role fixes its contribution before learning the honest contribution; mismatch or uncertainty burns the pair]
    confidence: 0.99
  - id: SPEC-012
    source: phase-d-bounded-assurance-v1.json; oracle manifest
    statement: Oracle parity proves bounded semantic compatibility, while constant-time evidence excludes variable-time division and sqrt opcodes and leaves branch dataflow and runtime behavior unclaimed.
    preconditions: [exact pinned oracle tree, exact reviewed Wasm artifacts]
    postconditions: [compatibility evidence and explicit non-claims]
    confidence: 0.99
```

## Code-IR

```yaml
code_ir:
  - id: CODE-001
    surface: crates/router-ab-ecdsa-presign/src/lib.rs:206-415
    entrypoints: [AdditiveKeyShare::from_bytes, ClientPresignInput::new, SigningWorkerPresignInput::new, start_client, start_signing_worker, role-specific receive, PresignOutput::into_parts]
    behavior: Parses canonical shares, fixes lambda per role, consumes role states, checks eG=E and the alpha/beta commitment equations, and emits only local k/sigma material.
    confidence: 0.99
  - id: CODE-002
    surface: crates/router-ab-ecdsa-presign/src/session.rs:113-476
    entrypoints: [derive_presign_pair_context, ClientPresignSession::{new,stage,poll,message,start_presign,take_presignature_97}, SigningWorkerPresignSession::{new,stage,poll,message,start_presign,take_presignature_97}]
    behavior: Derives a protocol/key/session-bound pair context, poisons a role session before message processing, and permits one output take after the fixed driver completes.
    confidence: 0.99
  - id: CODE-003
    surface: crates/router-ab-ecdsa-presign/src/driver.rs; codec.rs
    entrypoints: [start_client_driver, start_signing_worker_driver, fixed role-state receive methods, fixed round encoders and decoders]
    behavior: Implements eleven compile-time role rounds with fixed message layouts, exact sender/round/context checks, zero flags, size bounds, and no generic topology input.
    confidence: 0.98
  - id: CODE-004
    surface: triples.rs; proofs.rs; triples/finalize.rs
    entrypoints: [commit role polynomials, verify role openings and private shares, prove and verify role DLog/DLogEq, prepare and receive role triple finalization]
    behavior: Commits and verifies polynomial evaluations, generates prover nonces internally in production, binds proof transcripts, checks cG=C+zL and the terminal public product equation, then constructs ValidatedTriple.
    confidence: 0.98
  - id: CODE-005
    surface: triples/base_rot.rs; triples/base_rot/extension.rs
    entrypoints: [role-specific base-ROT start/receive, role-specific extension start/receive/prove/accept]
    behavior: Uses fixed 128-base/1024-row/768-output parameters, keyed context-bound row expansion, post-correlation challenges, eight chi rows, unreduced CLMUL checks over every column, and authenticated acceptance before receiver output release.
    confidence: 0.96
  - id: CODE-006
    surface: triples/base_rot/extension/mta.rs
    entrypoints: [role-specific multiplication sender start, ciphertext receive, response receive, role share combine]
    behavior: Consumes two disjoint 384-OT slices in each direction and constructs additive MTA cross-term shares under fixed role/triple schedules.
    confidence: 0.96
  - id: CODE-007
    surface: crates/router-ab-ecdsa-online/src/lib.rs:57-367
    entrypoints: [combine_rerandomization_contributions, role material from_bytes/reserve, role online input new/commit, compute_client_signature_share, finalize_signing_worker_signature]
    behavior: XORs two fixed 32-byte contributions before the existing context-bound HKDF, and enforces type-state reservation/commitment, exact R binding, fixed lambdas, low-s selection, registered-key verification, and recovery binding.
    confidence: 0.99
  - id: CODE-008
    surface: crates/router-ab-ecdsa-pool/src/lib.rs:183-675
    entrypoints: [AvailableRecord::{new,reserve,expire,retire}, ReservedRecord::{commit,destroy,recover_after_crash}, CommittedRecord::{finish,recover_ambiguous_delivery}, PoolMutation accessors]
    behavior: Makes lifecycle branches distinct types, enforces revisions and bindings, and replaces all used or uncertain material with tombstones.
    confidence: 0.99
  - id: CODE-009
    surface: packages/sdk-web/.../ecdsaPresignMaterialStore.ts:665-1105
    entrypoints: [store, reserve, commit, takeForOnline, recover, retirePool]
    behavior: Encrypts 97-byte client material under AES-GCM with identity-bound AAD, performs lifecycle updates in IndexedDB read-write transactions, writes a tombstone before decrypting and returning online material, and destructively recovers ambiguous states.
    confidence: 0.98
  - id: CODE-010
    surface: crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs:329-757; durable_object/worker_storage.rs:716-733; lib.rs:9976-10075
    entrypoints: [apply_cloudflare_signing_worker_ecdsa_pool_command_v1, reserve, commit, finish_committed, recover_after_crash, durable mutation and finalize handlers]
    behavior: Applies exact-scope CAS transitions in one Durable Object record replacement, persists committed before online signing, persists terminal tombstone before response, and burns ambiguous recovery.
    confidence: 0.98
  - id: CODE-011
    surface: Wasm client and SigningWorker presign wrappers; Wasm online client wrapper
    entrypoints: [ClientPresignSession methods, SigningWorkerPresignSession methods, compute_client_signature_share, init exports]
    behavior: Exposes only fixed-role sessions and the client online share operation, uses OsRng in presign, validates fixed byte lengths, and zeroizes copied secret inputs after use.
    confidence: 0.98
  - id: CODE-012
    surface: router-ab-core/src/protocol/router_ab_ecdsa_derivation.rs:1846-2180; router-ab-cloudflare/src/lib.rs:9607-10083; signing_worker/mod.rs:670-725,942-1014; packages/sdk-web/.../presignaturePool.ts:1087-1245
    entrypoints: [prepare commitment and response, finalize opening reconstruction, durable pool reserve/commit/finish, client and SigningWorker online invocations]
    behavior: Client samples and commits C; SigningWorker samples W after admission, persists it before reveal, and returns it; finalize reconstructs the committed prepare digest from C; durable mismatch burns before committed presign material access; both roles XOR C and W and zeroize transient copies.
    confidence: 1.00
```

Production presign exposes `session` plus the opaque presign input/output types.
Proof, polynomial, ROT, extension, MTA, and finalization symbols are private unless
`test-utils` is enabled. The Wasm surface consists of fixed Client and
SigningWorker presign operations, one Client online-share function, and the
separate derivation bootstrap already owned by the SigningWorker package.

## Alignment-IR

| Alignment | Spec | Code | Classification | Confidence | Evidence |
| --- | --- | --- | --- | ---: | --- |
| `ALIGN-001` | `SPEC-001` | `CODE-001` | `full_match` | 0.99 | `presign/src/lib.rs:356-415` enforces all three public equations before output |
| `ALIGN-002` | `SPEC-002` | `CODE-002`, `CODE-003` | `full_match` | 0.99 | role states and fixed codecs cover rounds 1 through 11; session state is consumed or poisoned |
| `ALIGN-003` | `SPEC-003` | `CODE-004` | `full_match` | 0.98 | opening digest and recipient evaluation checks bind role, pair, and triple |
| `ALIGN-004` | `SPEC-004` | `CODE-004` | `full_match` | 0.99 | production proofs accept `CryptoRngCore`; caller-supplied nonce paths are test-only |
| `ALIGN-005` | `SPEC-005` | `CODE-005` | `full_match` | 0.97 | degenerate points and context/reflection substitutions abort before key release |
| `ALIGN-006` | `SPEC-006` | `CODE-005` | `full_match_with_assumption` | 0.95 | keyed expansion fixes the pinned upstream defect; consistency acceptance depends on authenticated transport as stated |
| `ALIGN-007` | `SPEC-007` | `CODE-006` | `full_match` | 0.96 | MTA algebra reconstructs both cross terms; terminal finalization detects altered ciphertexts |
| `ALIGN-008` | `SPEC-008` | `CODE-004` | `full_match` | 0.98 | opaque triples arise only after proof, public product, and private-share checks |
| `ALIGN-009` | `SPEC-009` | `CODE-007` | `full_match_with_assumption` | 0.98 | XOR feeds the unchanged context-bound HKDF; equations, key verification, recovery, and one-use typing match |
| `ALIGN-010` | `SPEC-010` | `CODE-008`, `CODE-009`, `CODE-010` | `full_match_with_platform_assumption` | 0.98 | browser transactions and Durable Object serialization implement forward-only replacement and terminal burn |
| `ALIGN-011` | `SPEC-011` | `CODE-012` | `full_match_with_assumption` | 0.99 | exact commitment/opening reconstruction, post-admission Worker sampling, persisted reveal, XOR composition, and terminal mismatch burn implement the one-sided public coin |
| `ALIGN-012` | `SPEC-012` | oracle and constant-time tests | `full_match` | 0.99 | exact oracle tree/digests pass; opcode scans pass while branch warnings remain explicitly unproved |

## Equation and composition review

Let `d_C + d_W = x`, `lambda_C = 3`, `lambda_W = -2`, and
`x_i = d_i / lambda_i`. The reviewed triple finalization constructs additive
`a`, `b`, and `c` with `c = ab`. Its two directional MTA executions supply the
cross terms while each role retains its local product, so the sum is

`a_C b_C + a_C b_W + a_W b_C + a_W b_W = (a_C+a_W)(b_C+b_W)`.

The proof layer checks DLog ownership, DLogEq consistency for the same exponent,
the public product commitment, and each recipient-private product-polynomial
evaluation. A `ValidatedTriple` is therefore a post-verification type.

Presign reconstructs `e = e_C + e_W` and requires `eG = E`. It sets
`R = e^-1 B_0`, reconstructs `alpha` and `beta`, and requires
`alpha G = K + A` and `beta G = X + B`. Each role emits
`sigma_i = alpha x_i - beta a_{1,i} + c_{1,i}`. With a shared nonzero
rerandomizer `delta`, online signing uses `R' = delta R`, `k'_i = k_i/delta`,
`sigma'_i = sigma_i/delta`, and
`s_i = lambda_i(h k'_i + r sigma'_i)`. Summation yields a standard ECDSA `s`.
The SigningWorker performs low-s normalization, full signature verification
against the registered group key, and recovery-ID binding before output.

For OT extension, each keyed row expansion binds suite, scope, pair, triple,
sender, base index, branch, and block. The receiver correlation message has the
IKNP form `u = t_0 xor t_1 xor choice_mask`; the sender derives its correlated
row with its hidden base choice. A fresh post-correlation challenge derives eight
chi rows. Unreduced carry-less multiplication checks all 128 columns in one
constant-time aggregate decision, and the receiver output stays sealed until an
authenticated acceptance digest arrives. MTA consumes disjoint OT ranges and
terminal product checks provide the final integrity boundary. I found no
algebraic or index-schedule divergence in this composition.

## Transcript and party-view review

Presign pair derivation binds the protocol identifier, registered group key, and
length-prefixed presign session ID. Polynomial, proof, base-ROT, extension, MTA,
finalization, presign, and online derivations use separate domains and bind the
role, scope, pair, triple index, proof/message kind, statement points, and fixed
indices required by that stage. Fixed codecs reject wrong sender roles, rounds,
flags, lengths, trailing bytes, and substituted contexts.

The normal transcript exposes commitments, proofs, role-local encrypted or
masked messages, public `R`, a Client signature share, and the verified final
signature. It does not expose a peer additive key share, raw MTA share, unchosen
OT branch, receiver choice vector, or Deriver root-share material. These
conclusions rely on authenticated private peer transport and the tested
Cloudflare/client ownership boundaries.

## One-use persistence review

The Rust pool domain uses distinct available, reserved, committed, and tombstone
types. Binding failure, timeout, peer abort, crash recovery, ambiguous delivery,
and epoch retirement are terminal. The browser store encrypts live material and
atomically replaces its record with a secret-free tombstone before returning
decrypted material to the online worker. The SigningWorker Durable Object applies
an exact-scope, exact-revision reducer, persists committed state before signing,
and persists the terminal tombstone before returning a signature. A failure after
commitment yields no reusable record; recovery burns it as ambiguous.

This conclusion assumes IndexedDB transaction durability and Cloudflare Durable
Object serialized storage behave as their platform contracts specify. The source
and focused tests cover local races, stale revisions, cancellation, timeout,
crash recovery, ambiguous output, and retirement.

## Oracle and constant-time scope

The oracle manifest pins NEAR commit
`db609be5021eb9d794f577601f422818fbdfe246`, tree
`05f60d54971e2f1e417dab7191f0f5d02f82468c`, 23 source files, seven vectors,
and the four-case semantic replay digest. The random-OT row bytes are deliberately
excluded from exact parity because the pinned source finalizes an unkeyed hasher
clone. The local keyed construction has its own sensitivity regression. This is
a sound separation between semantic compatibility evidence and construction
security.

Optimized native ARM64 assembly analysis found no high-confidence variable-time
division or square-root instruction in either reviewed cryptographic crate. The
online crate produced 93 conditional-branch warnings, matching the pinned phase-D
evidence. The release-Wasm guard also passed. No secret/public dataflow proof was
performed for those branches, no JavaScript-engine timing guarantee was assumed,
and no end-to-end constant-time claim is approved.

## Findings and resolutions

### `RAR-01` — public rerandomization coin

- Original severity: **high**
- Superseding status: **resolved**
- Confidence: **0.99**
- Affected claim: active security with either single role corrupt, plus
  `upstream-check-inventory.md` row `RER-03`

The Client samples uniform `C`, sends
`SHA-256("router-ab-ecdsa-derivation/client-rerandomization-commitment/v1" || C)`
in prepare, and retains `C`. After exact Router admission and materialization,
the SigningWorker samples uniform `W`, stores it in the request-bound reserved
record, and reveals the persisted value. Finalize opens `C`; the reconstructed
prepare digest must match the reservation before committed presign material is
accessible. Both roles pass `C XOR W` to the existing scope-, key-, digest-, and
`R`-bound HKDF.

For a corrupt Client, its commitment is fixed before the honest SigningWorker
samples `W`; XOR with uniform `W` is uniform. For a corrupt SigningWorker, the
honest uniform `C` remains hidden when the Worker chooses and persists `W`;
under `A-COIN-COMMIT`, the Worker cannot predict `C XOR W` or later change the
Client opening. The protocol therefore supplies unpredictability at each corrupt
role's contribution choice point.

Substituted openings reconstruct a different prepare digest and produce a
durable `BindingRejected` tombstone before presign material access. Replayed
prepare or finalize operations fail the exact revision/request binding; timeout,
withhold, crash, and ambiguous delivery also end in burn. A corrupt role may
selectively abort after learning the combined coin and thereby condition the set
of completed attempts. Each attempt consumes fresh one-use material, and the
approved claim explicitly excludes fairness and availability. No reusable
presign state or adaptive contribution substitution follows from that abort.

The prepare/finalize route count remains two. The added commitment and reveal are
fields in those existing calls. This resolves the original contradiction without
changing the reviewed presign equations or online signature algebra.

## Required decision checklist

| # | Decision | Rationale |
| ---: | --- | --- |
| 1 | `accepted` | Fixed parameters, roles, equations, role-state transitions, and terminal commitment checks match the code. |
| 2 | `accepted` | Within `A-OT-CORRECTED` and authenticated transport, keyed expansion, all-column consistency, sealed receiver release, disjoint MTA indices, and terminal product checks support the bounded malicious-OT claim. |
| 3 | `accepted` | Upstream row `RER-03` matches the reviewed Client commitment, post-admission Worker reveal, finalize opening, XOR, and terminal mismatch burn. |
| 4 | `accepted` | Reviewed normal views and fixed boundaries reveal no peer additive key share, raw peer MTA share, receiver OT choices, or Deriver root-share material. |
| 5 | `accepted` | Domain and proof bindings are complete, and the public coin is unpredictable at either corrupt role's contribution choice point under `A-COIN-COMMIT`. |
| 6 | `accepted` | The pinned oracle matrix and corrected-extension divergence cleanly separate compatibility from security evidence. |
| 7 | `accepted` | Client and SigningWorker persistence implement forward-only CAS, pre-use commitment, terminal tombstones, and destructive recovery for every reviewed uncertain exit. |
| 8 | `accepted` | Constant-time evidence is accurately limited to opcode scans and Wasm guards; branch dataflow, JS timing, and runtime constant-time behavior remain explicit non-claims. |
| 9 | `accepted` | Production and Wasm APIs expose fixed Client/SigningWorker operations and preserve registered-key verification and recoverable low-s output. |

## Verification commands and results

| Command | Result |
| --- | --- |
| `cargo test --manifest-path crates/router-ab-ecdsa-presign/Cargo.toml` | pass: 44 unit tests and 7 compile-fail doc tests |
| `cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_derivation_protocol` | pass: 57 protocol and commitment/opening tests |
| `cargo test --manifest-path crates/router-ab-ecdsa-online/Cargo.toml` | pass: 2 unit tests and 5 compile-fail doc tests |
| `cargo test --manifest-path crates/router-ab-ecdsa-pool/Cargo.toml` | pass: 8 unit tests and 1 compile-fail doc test |
| `cargo test --manifest-path crates/router-ab-ecdsa-wire/Cargo.toml` | pass: 1 unit test |
| `cargo test --manifest-path crates/router-ab-ecdsa-near-oracle-tests/Cargo.toml` | pass: oracle provenance, vectors, parity, abort index, production boundaries, upstream inventory, and Wasm opcode guard |
| `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml` | pass: 332 tests total across unit and integration targets |
| focused Cloudflare derivation and pool-lifecycle filters | pass: 51 derivation cases and 4 pool mismatch/replay cases |
| `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/ecdsaPresignMaterialStore.unit.test.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts ./unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts --reporter=line` | pass: 24 tests |
| focused normal-signing boundary and generated-worker pool waterfall | pass: 7 browser tests |
| three ECDSA ownership, derivation-boundary, and identity source guards | pass |
| optimized ARM64 presign assembly scan | pass: 3,884 functions, 29,311 instructions, zero high-confidence findings |
| optimized ARM64 online assembly scan with branch warnings | pass: 629 functions, 4,194 instructions, zero high-confidence findings, 93 warnings |

## Reviewed source-tree manifest

The working tree contained uncommitted implementation changes, so the base Git
commit alone does not identify the reviewed bytes. This manifest is the decision
receipt. Paths are bytewise sorted. Each canonical record is
`lowercase_sha256`, two ASCII spaces, the repository-relative path, and LF. The
SHA-256 of all 122 canonical records, including the final LF, is
`68a9981a189c8b88acc6eec9d970e16bb864f2bfb4289815d2f82aa32460985e`.
The decision document itself is excluded so the receipt can be recorded without
changing the reviewed root.

```text
ff7afbe12eefd7e1e52892ab17ce504ecc9847a3bcdb45dbc2dafdb73a48e4b3  crates/router-ab-cloudflare/Cargo.lock
f89b46182145f269ae9fd32657849e53e122870e397a4112710ad0d5e02e1535  crates/router-ab-cloudflare/Cargo.toml
1ddf36cbef181f31144ed7195c53d637badba5d6a658769a1b1f5f6509e062c4  crates/router-ab-cloudflare/src/durable_object/handlers.rs
ff0e19ec265bf64225d593bfd41a6d460d056fc6c80c80bbbbc952a86932bad7  crates/router-ab-cloudflare/src/durable_object/memory_storage.rs
64c722992b95c4960315745ac53efd18c7f77b7098602b82c473fe6b2b320d45  crates/router-ab-cloudflare/src/durable_object/mod.rs
df34208c85f5df5011845c0f9fcb3d47e4a5187a4a0a3dfbd25dc9f20f302849  crates/router-ab-cloudflare/src/durable_object/worker_storage.rs
67d0cc71e8c98b550a446a8f4262d612ccac0074e93704c4a1b20be6a1e9057f  crates/router-ab-cloudflare/src/ecdsa_normal_signing_transport.rs
90ffe9cd5e615f4a60322616627eda9f5d3cea8aa7561a16ad54d933ca4a10a3  crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs
cd603e51b4a6b774d81df343fa39ea326d51eb024b24e8aace55f5fa74fee202  crates/router-ab-cloudflare/src/lib.rs
10ace1439118fbb0f0c3bb3a2fb014dcbaafabb73bfc380cb9c407cc4b32d210  crates/router-ab-cloudflare/src/signing_worker/mod.rs
842fd9a0b1ca723e8b6c8748ba26874022daef4a2cb7c0023b84290d1e44275d  crates/router-ab-cloudflare/tests/bindings.rs
9771183794a18b6a611e3edba1334c614418248472d22db9ef2db4a493c1d7b1  crates/router-ab-cloudflare/tests/ecdsa_commitment_policy_trust_boundaries.rs
1d430be963e228075954c5b132c201a0830e7241d2cf5fb489cb9ecd33f722d9  crates/router-ab-cloudflare/tests/ecdsa_derivation_activation_boundaries.rs
2839754f9ffe96460ed355572e7127079054c5bfa4384bff01c0d85a6916cfbe  crates/router-ab-cloudflare/tests/ecdsa_derivation_lifecycle_matrix.rs
939656611e28301259d569f035de6d7387ed531dda2398735528caa955b9f322  crates/router-ab-cloudflare/tests/ecdsa_derivation_normal_signing_boundaries.rs
74654b1959fdbee2224ccdbc688d8ed3536a47ede5547daa25e6acd5677d06ef  crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs
51bada41dff9829fbb2614c910db353649a4e9a5d262b26f750ef24448796b1b  crates/router-ab-cloudflare/tests/route_paths.rs
c4c06c585cf86c69899cbda7f3de7c61017dcba4f13358daa2b82a0181c4df51  crates/router-ab-cloudflare/tests/secret_material_boundaries.rs
c390a41000ed811eaf8be0315a3ec8abb1fb0970a0bcc625c6ec6caccefe7f1c  crates/router-ab-cloudflare/tests/strict_router_cors_boundaries.rs
2518221d1d03b36671e1bac275d8045d3b6ff1854cc91b0ee5d5429300cd9441  crates/router-ab-cloudflare/tests/strict_router_route_boundaries.rs
a2b1cf97be0bd8e20de4eb243508f7aa4e77632221543f3807330950157b5856  crates/router-ab-cloudflare/tests/vector_adapters.rs
305b6d85eb2fb4d52f67d67455d41f5ca0b0d9eed6bc1bb55a12832cec30942d  crates/router-ab-cloudflare/tests/wasm_vector_adapters.rs
63ce1c2d2f44953788a4941c0066c00e44f75a62372b4b85a10f382097b89237  crates/router-ab-core/src/protocol/mod.rs
074998bee5e435c37ed1c6402be1736a483c36d0531316e6ee9defff9535c350  crates/router-ab-core/src/protocol/router_ab_ecdsa_derivation.rs
efbf69e1638635715384e74b1a788a15e34c59fc8a477789ca37f6a41adc8f4c  crates/router-ab-core/tests/ecdsa_derivation_protocol.rs
cb6acfae1d881b7853c3f9ddcc7c77c908aaef7ad10103fbe3326cc74aced007  crates/router-ab-dev/src/bin/router_ab_local_release_evidence.rs
1bf07865e6cc8e0170921247907085f78054dc287d8446032f9ee50d2e039b66  crates/router-ab-dev/src/bin/router_ab_local_smoke.rs
34d729a04ff37cded3ff20e826d02c1f8debdda7ecb2f4a64eea948a6189af80  crates/router-ab-dev/src/lib.rs
5c6fbe0eddbf1c2a6b9284b60280c9c06c6e1e7ebea5f1e9f34528ffeab3dfcd  crates/router-ab-dev/src/local_router_ab_ecdsa_derivation_pool_store.rs
4521ac7304d47aded5236b7747103abd041667e2a3da45e6145a6b946fe2cdba  crates/router-ab-ecdsa-near-oracle-tests/Cargo.lock
22183e763ef9e7ff9ec1d19351a81ba1612e7c54a918513744cdc4c817c733ac  crates/router-ab-ecdsa-near-oracle-tests/Cargo.toml
0e38983aebc110b4f0407a6b2d0349b3e398b373e0639472e1510e47113fc577  crates/router-ab-ecdsa-near-oracle-tests/fixtures/v1/manifest.json
3892ab5321a5c0152cc4ed5303c1d5db7d98e71cb30ca40691ebaffbe5e1a8cf  crates/router-ab-ecdsa-near-oracle-tests/src/lib.rs
6f80947ceab2c70f46132e70907a4c9ae972c3e615e489459110654f1aba1c7e  crates/router-ab-ecdsa-near-oracle-tests/tests/abort_corpus_index.rs
81e61a47931e171875590c7946ee1443499322e1cd163604ad6f07b31d676007  crates/router-ab-ecdsa-near-oracle-tests/tests/base_rot_vectors.rs
214e9d9e1619edc310841f0fe2c17f8549e00d5ab419e82860c3c71b5696fae4  crates/router-ab-ecdsa-near-oracle-tests/tests/mta_vectors.rs
51c1a18ccac83244c4afff915b8f903b04593e0452502f88c081f4870c7d083d  crates/router-ab-ecdsa-near-oracle-tests/tests/online_parity.rs
a45c7ebd1a5070323e7d1a9c6052f68146126ab966417383a0cf891a3b338968  crates/router-ab-ecdsa-near-oracle-tests/tests/oracle_manifest.rs
e2f738b75590b449d65e34a25f9e70c3b5a73cfa5602192d223200a451cf4802  crates/router-ab-ecdsa-near-oracle-tests/tests/polynomial_vectors.rs
88d7c92654383a436e4fe13806f1869e3f507e48d787167600c8dadf08d3bb3e  crates/router-ab-ecdsa-near-oracle-tests/tests/presign_parity.rs
c6a896159a5250d2f7d815a39daf17c505b5015f9faefe61627d4083f07a9dc5  crates/router-ab-ecdsa-near-oracle-tests/tests/production_boundaries.rs
f10e56611163dc9602b86b6c166af9f9568161cae95c36106f73b1178ba51774  crates/router-ab-ecdsa-near-oracle-tests/tests/proof_vectors.rs
3aa1a3627cdcb4a4d0c95f69a467ed59a0190872ae15c53e5cc59cb286935b6b  crates/router-ab-ecdsa-near-oracle-tests/tests/random_ot_extension_vectors.rs
d974b7049baf0179e394a26b279d697789ef5799b011e02c660537c8d5c14798  crates/router-ab-ecdsa-near-oracle-tests/tests/upstream_check_inventory.rs
855ee034707e1001e9f7d998c05ab760485f2522d424a1486519e693916f07d7  crates/router-ab-ecdsa-near-oracle-tests/tests/wasm_constant_time.rs
d9e6ced291274735829adf970d9465321938dcf26a66c7b29a38141a7c4ae535  crates/router-ab-ecdsa-online/Cargo.lock
f1020f71db5dd3a4a10eb7c1b4f177db1372bdd1a3060fead8614769a9d755dd  crates/router-ab-ecdsa-online/Cargo.toml
7de84596087ffd4b69c4f140d9a856f5dde72091441d0c064362d846467aa7e0  crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md
d9aba9a3cc2d230de2b453a7e82a2ed1c781b23cb4eb3a45290a37bf2bd0fb0e  crates/router-ab-ecdsa-online/src/lib.rs
dad66d027bd78b68868bfeccafa6d9dd6c2f426e7dea1fe12a86d17a6df0b584  crates/router-ab-ecdsa-pool/Cargo.lock
eed3b88e93ab184d1196f48ab20c55148cd552551249936ccebfc938fe5ec00e  crates/router-ab-ecdsa-pool/Cargo.toml
1fa79931d6bbd056384b75f62abf4397485af471c42921d346efc8c968e83f93  crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md
e588fec5eefe8a3c9d7dd272b1361103109d85df19b5ac8eac34b3a79f830a7e  crates/router-ab-ecdsa-pool/src/lib.rs
f27a0d19434585c2442efa37f012fb0afc749d0f458868687a3ef4aaa1677476  crates/router-ab-ecdsa-presign/Cargo.lock
968636c9ef29c261798bcacc3eb124752721fdd4d9c44005faf7fb033fa64142  crates/router-ab-ecdsa-presign/Cargo.toml
8c18537bb548740cc667039bce5f315b755b9a68634ba9760f98c17fc974d87f  crates/router-ab-ecdsa-presign/specs/abort-corpus-v1.md
9cb381cbf9decdd687cfbe3ab6b28b223c484d8877185f228bd1abec681ceda8  crates/router-ab-ecdsa-presign/specs/assurance-ledger-v1.md
bf5a5d5bea4e843d3cc725bf1f60a8e7569a8d743b3ad7272b24adc0e22de59e  crates/router-ab-ecdsa-presign/specs/base-rot-v1.md
45defbe4eab65a61cecb6981aa9640a9accb35ced836bc74e45ce0907dab30a6  crates/router-ab-ecdsa-presign/specs/committed-triple-finalization-v1.md
8f9fa720bc39b60adc37f1a86aaff176c4bd5f130abfbd6796941461b97d9222  crates/router-ab-ecdsa-presign/specs/fixed-driver-v1.md
81d866ef2bdf05b14b1861deb79e821b64f3830f0a86a1225239e99782bea74c  crates/router-ab-ecdsa-presign/specs/fixed-mta-v1.md
17a43dec29e61752c91ff0516c8a52ab6efecee48ae2a5d61ceaad1173a30fa0  crates/router-ab-ecdsa-presign/specs/polynomial-commitments-v1.md
bbc8d79b4c072d7c9e8128c30d38cbc5cc21d00213fb2e8cb60e32509136816b  crates/router-ab-ecdsa-presign/specs/proof-kernel-v1.md
6f08665b1bac22e3f5f0c50c1d3c4dec6ea1f1bbdd2b038393d22fbfa4159ca2  crates/router-ab-ecdsa-presign/specs/prototype-security.md
4e52cb2c7503d98d577363d5ba8fc3f7d241631de23021f93ab0bcc954105b80  crates/router-ab-ecdsa-presign/specs/random-ot-extension-v1.md
99b5bf4b967be2ea5bebfed4aaa9ac7b09f962b7ca3016337136b46e0c31a5f2  crates/router-ab-ecdsa-presign/specs/upstream-check-inventory.md
efe16660d0e931a2719f04d8820a02d8bdd21f59c300dea471ea6afc11921bc7  crates/router-ab-ecdsa-presign/src/codec.rs
66e06d8aafb20a075f91212092fc99435378ee653e4eadf9e80c5bb6bebc3577  crates/router-ab-ecdsa-presign/src/driver.rs
e7565944e85391f20f506cca810df3a0f5aed577355daa019f1892f5da168bda  crates/router-ab-ecdsa-presign/src/lib.rs
639ff608b95aea2f6462ee4782c26272402f52edb98886672f037b66fd2c93af  crates/router-ab-ecdsa-presign/src/proofs.rs
1e2db42ffda5faa9316c6650c1e24fbb1bbb3ad4d1d6caef2a9c5a5c5f0ea314  crates/router-ab-ecdsa-presign/src/session.rs
716213040ff12106580d7b71bac2d18ffb88b7ebc2fa0e19ffd9e0438f15e3ea  crates/router-ab-ecdsa-presign/src/triples.rs
7da42af02f8a0953620c410e854971bf9b6b95c239b5620c4c43053769931bf5  crates/router-ab-ecdsa-presign/src/triples/base_rot.rs
a38e5ed04810cc60f9d6542f65c2b65f3094464b77df24820b39be2194ba355b  crates/router-ab-ecdsa-presign/src/triples/base_rot/extension.rs
8469001d2679a5c45dc4267552fd276c4ef24b0b663cbe1d79d0f2afcf8d5975  crates/router-ab-ecdsa-presign/src/triples/base_rot/extension/mta.rs
822f4bd6ae2ffc40250905b55bdbd38653f545a81d56e252eab940f8f9543979  crates/router-ab-ecdsa-presign/src/triples/finalize.rs
3d16e91c60f1f9f0414270f406cfdc25a6af36d38ec62e4287c4b802e55ee403  crates/router-ab-ecdsa-wire/Cargo.lock
60118933229f76d86090945a7c861cade04c4c214dc74c49821db904143b345b  crates/router-ab-ecdsa-wire/Cargo.toml
87f80837abb0f7f211eabcb26e013678e056b81f26ee5dc59942840a0fa52ac9  crates/router-ab-ecdsa-wire/src/lib.rs
5b86075079103e05b6a79e60469b732f2f0080e5995426e0e02d8f91bcd500fb  docs/evidence/refactor-89/phase-d-bounded-assurance-v1.json
cc639cbcdf0703dd2bffda44ea771fef70ec8d0feccf15a82d9b8784887ee79e  docs/evidence/refactor-89/phase-e-local-artifacts-v1.json
b020ed1b9944a7064fcf4ff487d92eddc480ddd50d523bb8a02aebdf726f5e0e  docs/evidence/refactor-89/rar-01-public-coin-remediation-v1.md
aeb6c9bc2d4afcf67d3a1ca9a8652eadd89d020708e1c9fd8fab3553e869c3ba  packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts
f4b660ad791b7aa9dc30889bd4242496f7f49cdfab9fcf8adf701bae3699dd86  packages/sdk-server-ts/src/core/ThresholdService/routerAbEcdsaSigningWorkerWasm.ts
129f7335820a1f3f6252998e3580ad787afa7cbe42651047cf0eb51959668455  packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts
25c2cb8601e9835a44752821bb9ad610a751de737508af5bc20005cf4a41fcce  packages/sdk-web/dist/public/sdk/workers/ecdsa-online-client.worker.js
bbe99f7aaa6943283dc8634fef6923971db629aea71028049e21678d808d9ee7  packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts
a83170d78fddcd6cc6afc03208cea553a5c92130c600834a66cdd583e6af04e0  packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.typecheck.ts
df65dfd15256f3b584545dd886f8b2106ee32d67876174aaff059d536b2ea6a4  packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/ecdsaDerivationClientSigningMaterialSource.ts
b859260a928d85ae641d3ef499a5b200830b1d4996cefc4c6a616f99b831618f  packages/sdk-web/src/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool.ts
da10ebfb6ba7ee6427fc6b204b36faf556015ba4818fa1bff30e5f712d8298e1  packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefillSigningMaterialSource.ts
93cba564ca64dba8337ba4a9b5380542aa57109ceaadd0fd82910a22a0f4da00  packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts
2e33fe417e777786f8305c296cd246e057dcd7c32ac87b4804292f130b12d280  packages/sdk-web/src/core/signingEngine/workerManager/ecdsaClientWorkerChannels.ts
b0cd1afff00f3a7816206e1999827e8af97820257319d84843dedf65deb689f4  packages/sdk-web/src/core/signingEngine/workerManager/ecdsaPresignPoolIdentity.ts
b9edd6deedea88e46e864d25f575c7eee978a7416cebc2f024ebda97fa96b8af  packages/sdk-web/src/core/signingEngine/workerManager/workerTransport.ts
dd350fa4fe40d0c1549f8961a6a66ab85048df339e0919c5573c69715d103012  packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts
84105eaee512d37035eb50a41c8f43e4fa917bcf04088ff5fce5d0e2ca657a3f  packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.typecheck.ts
3b8e3ba6ba583271ffd70a313918b13e01321d007cdf89247e0ab84414faa1dd  packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-online-client.worker.ts
c6802cc7c3b28c71fefa46735ebf8d292bfc22a743022979ae17705dbe4efa1e  packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-presign-client.worker.ts
bf3fb141ab54009073963b5f7d0442ad5451a4176a979f3316b8fe21ad1011a7  packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaPresignMaterialStore.ts
58c3481b6e479e19ff89d8ef92ae4c0403debb30fa30a28b9b1efb2dc0f8c35f  packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts
7b19a96e1fbdfad5c7fe729d8e1e12717aea63521c0a5576bc81270a002a3dd7  tests/scripts/check-ecdsa-client-worker-split.mjs
7c0eb8d36d536afab64dec139bbd20490bd051c7160d6ae07600aed87f209123  tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs
4f3233e78b6f2b7842cfc3540267650099086bc145c86d9ca1f6bf9d20e07678  tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs
e9c8dc67ef59ffa15935b63499565792ba408d1682aa531bf9a6a2dc02af02bc  tests/unit/ecdsaPresignMaterialStore.unit.test.ts
b82f873a8036c4393ac609331101308b8ce07e22865c837cc0f58f0aa237976e  tests/unit/routerAbEcdsaDerivationNormalSigning.unit.test.ts
7f3675b47d3cce47e48e94838b75cbbd8b9b73eda3496148eb7d89a7e2881a4c  tests/unit/routerAbEcdsaPoolHitWaterfall.unit.test.ts
0e14644d78e9306a34cbb48cd9ca139bbe75e268149ca9fb7a15046fc900567c  tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts
b497a0ce176f6674b0a663a99b0134ccc9e4e3049a07786b48a5a79d4b866fde  tests/unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts
5af086e166f3767f987961102572e61c31b488d2401e565e12077cbce1e15eb4  wasm/router_ab_ecdsa_online_client/Cargo.lock
31df9bf890ffacea80cb592319478cdcd95a3678fee9baf491d3f32327513646  wasm/router_ab_ecdsa_online_client/Cargo.toml
05f441332aa7c410207e3df2fb8d1d73e1c874d351af9e92ac106655a2dab657  wasm/router_ab_ecdsa_online_client/pkg/router_ab_ecdsa_online_client_bg.wasm
2fcf085279e87efbaf8b64df739b0bcbf6dc0c779fe486b4ec27e7342fca50fa  wasm/router_ab_ecdsa_online_client/src/lib.rs
ad5bedc694ed94c46f07b950a14eb9a38d3e886746a627da538efb0be3183e39  wasm/router_ab_ecdsa_presign_client/Cargo.lock
11c7a1222d4e5863691dfbf2ec4e5a70f2b6f3314f487a28f147c712817cd582  wasm/router_ab_ecdsa_presign_client/Cargo.toml
eccaa0e994a6c8b28a049911ade87d3c4fe247e1b03af6b0ecdc747893fb1907  wasm/router_ab_ecdsa_presign_client/src/lib.rs
f6dee49f0650666bc9129d0340c715cc162f57184f74967640d7d748b11dd10c  wasm/router_ab_ecdsa_signing_worker/Cargo.lock
aaef2fe4372c7cf85fd08846a2ee54ef66ff4fb6da6f2d8245a5e8f8108b2528  wasm/router_ab_ecdsa_signing_worker/Cargo.toml
a1c274a1ccf5747422e7ca89d234974b55740538e810a0ec6cb7dc7656161410  wasm/router_ab_ecdsa_signing_worker/src/derivation.rs
9de797fd26cb7e26f1edd1190babc496bc58048f4d7a3208aa36caa8e62f7bfe  wasm/router_ab_ecdsa_signing_worker/src/errors.rs
fa5237fd5abe850041130e35f3cba39d1dda52e0068407c6285c9459eee1faad  wasm/router_ab_ecdsa_signing_worker/src/lib.rs
975a5302d32b98cc490f0a703a260d903ea07567cc5a3cf70a4d8bffe55a4a6e  wasm/router_ab_ecdsa_signing_worker/src/presign.rs
```

## Final decision

`APPROVED`

`RAR-01` is resolved. The one-sided commit/reveal construction supplies the
required public-coin unpredictability against either single corrupt role under
the stated assumptions and active-security-with-abort boundary. All approved
claims and retained non-claims are bounded to the exact manifest in this
receipt. The approval does not extend to the later Cloudflare SigningWorker
lifecycle delta.

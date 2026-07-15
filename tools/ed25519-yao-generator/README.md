# Ed25519 Yao Generator

This crate is a host-only reference oracle and test-vector generator for the
fixed Ed25519 derivation functionality. It is intentionally isolated from the
Router, Cloudflare Workers, SDK, transport, oblivious transfer, garbling, and
production protocol code.

The oracle evaluates:

```text
y_A = y_client_A + y_server_A mod 2^256
y_B = y_client_B + y_server_B mod 2^256
d = y_A + y_B mod 2^256, using little-endian addition
h = SHA-512(d)
a_bytes = clamp(h[0..32])
a = a_bytes mod l
tau_A = tau_client_A + tau_server_A mod l
tau_B = tau_client_B + tau_server_B mod l
tau = tau_A + tau_B mod l
x_client_base = a + tau mod l
x_server_base = a + 2*tau mod l
X_client = [x_client_base]B
X_server = [x_server_base]B
A_pub = Ed25519PublicKey(d)
```

Each Deriver input requires all four contributions: `y_client`, `y_server`,
`tau_client`, and `tau_server`. All four tau contributions must use canonical
scalar encodings. Validation errors identify the Deriver role and contribution
side. Callers populate named `RawDeriverAContribution` and
`RawDeriverBContribution` boundary values, which are consumed into validated,
field-specific domain types before evaluation. The oracle also checks the
intended algebra in tests:

```text
2*X_client - X_server = A_pub
```

`ActivationOracleOutput` has no seed field or seed accessor.
`ExportOracleOutput` always contains the reconstructed seed. Separate result
types keep lifecycle output states distinct without optional secret fields.

## Stable context and portable vectors

`Ed25519YaoApplicationBindingFactsV1` freezes the key-affecting SDK identity
facts as wallet ID, NEAR Ed25519 signing-key ID, logical signing-root ID, and a
positive `u32` key-creation signer slot. Its canonical encoder is:

```text
LP32(x) = BE32(len(x)) || x

LP32("seams/router-ab/ed25519-yao/application-binding/v1")
|| LP32("walletId") || LP32(UTF8(wallet_id))
|| LP32("nearEd25519SigningKeyId") || LP32(UTF8(signing_key_id))
|| LP32("signingRootId") || LP32(UTF8(signing_root_id))
|| LP32("keyCreationSignerSlot") || LP32(BE32(key_creation_signer_slot))
```

The binding digest is SHA-256 over that complete encoding. Every identifier is
one or more visible ASCII bytes in the inclusive range `0x21..=0x7e`; the
encoder performs no trimming or normalization. The key-creation slot is
immutable for one logical key; active/default and new recipient slots belong to
ceremony metadata. `nearAccountId` is excluded because an implicit account ID
derives from the final public key. Root versions, credential versions, epochs,
authorization, deployment, and transport values are also excluded.

For the committed fixture facts `wallet-fixture`, `ed25519ks_fixture`,
`project-fixture:env-fixture`, and key-creation slot `1`, the 213-byte preimage
hashes to
`b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121`.

`StableKeyDerivationContext` freezes the first Yao-era context encoding as:

```text
"seams/router-ab/ed25519-yao/stable-key-context/v1"
|| application_binding_digest[32]
|| participant_id_0_u16_be
|| participant_id_1_u16_be
```

The constructor accepts exactly two distinct, non-zero participant identifiers
and stores them in ascending order. The binding is SHA-256 over
`"seams/router-ab/ed25519-yao/stable-key-context-binding/v1" || encoding`.
Deployment, transport, ticket, request-kind, and authorization values are
excluded because they must not rotate wallet identity.

The committed portable corpus associates one synthetic clear-arithmetic case
with each canonical request kind: registration, activation, recovery, refresh,
and export. Its tagged case union makes an authorized seed result representable
only for export. A separately named `clear_reference_trace` records joined
host-only oracle values for differential implementations; those fields are not
party-visible protocol outputs. The trace includes `y_A`, `y_B`, joined `d`,
`tau_A`, `tau_B`, SHA-512 and clamp intermediates, both scalar bases, public
commitments, and the Ed25519 public key. RFC 8032 seeds and arithmetic wrap
boundaries are present in the portable cases.

Regenerate or check it with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json
```

Generate a larger deterministic differential corpus from public test material
with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-differential \
  --seed-hex 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a \
  --cases 128 \
  --output /tmp/ed25519-yao-differential-v1.json
```

For case index `i` and one-byte field tag `t`, the generator computes
`SHA-512(domain || 0x00 || public_test_seed[32] || BE32(i) || t)`. Tags `0x01`
through `0x08` produce the four `y` and four `tau` inputs; tag `0x09` produces
the application-binding digest. A `y` input uses the first 32 digest bytes. A
`tau` input reduces all 64 digest bytes modulo `l`. The request kind cycles in
registration, activation, recovery, refresh, export order. Differential seeds
are public reproducibility inputs and are never wallet material.

## Canonical ceremony-context DAG

`docs/ceremony-context-v1.md` freezes the public three-layer byte contract:
`PublicRequestContext -> Authorization -> CeremonyTranscript`. Both account and
wallet identity, tenancy, session, signing-root metadata, Router and Deriver-set
identity, role key epochs, chain target, replay nonce, client ephemeral key,
recipient plan, output package, and expiry are required before authorization.
All text identifiers use exact visible ASCII. Numeric versions and epochs use
nonzero BE64 values, with `protocolVersion` fixed to one.

`CeremonyValidatedDagV1` can only be built from matching request,
branch-authorization, and transcript objects. Activation control narrows an
origin witness from a coherent registration, recovery, or refresh DAG, commits
the derived origin kind and digests, and rejects current-context reuse. Export
and activation DAGs cannot become activation origins. Evaluation provenance
consumes the sealed DAG, encodes its branch kind, rejects activation, and
prevents cross-branch ceremony splicing.

The five-case corpus and all of its digests are public synthetic host evidence:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-ceremony-context \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json

cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-ceremony-context \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json
```

This module does not authenticate the opaque authorization, transport, or
artifact-suite digest slots. It handles no secret values and makes no
constant-time or deployed-protocol claim.

## Phase 2A provisional circuit IR, cores, schedules, and bundle

`docs/circuit-ir-v1.md` freezes the generator-owned Boolean IR and three
construction-independent benchmark components: SHA-512 over exactly 32 input
bytes, a provisional activation core, and a provisional export core. The
private builder emits only XOR, AND, and INV gates, folds constants, orders
commutative operands, prunes dead gates deterministically, and assigns implicit
gate-output wires in canonical topological order. Every canonical binary IR
header binds the component tag and exact input/output schema digests.

The activation input order is A `y_client`, `y_server`, `tau_client`,
`tau_server`, followed by the same four B fields. Its result contains only
`x_client_base` and `x_server_base`. The export input order is A `y_client`,
`y_server`, then B `y_client`, `y_server`; its result contains only the joined
seed. All fields use byte-major LSB0 bit order. Separate result and digest types
keep the seed-free activation component (`0x91`) disjoint from the `tau`-free,
seed-only export component (`0x92`).

The activation core composes 256-bit wrapping addition, fixed SHA-512/32, RFC
8032 clamp, exactly seven conditional-subtraction rounds modulo `l`, canonical
scalar addition, `tau` aggregation, and both scalar-output equations. Its host
harness validates all four public-synthetic `tau` inputs as canonical scalars
before evaluation. The Boolean core relies on that schema precondition and has
no `tau < l` comparator.

The frozen benchmark components are:

- Fixed SHA-512/32 (`0x81`): digest
  `11488ae3b47722d42d4fc7e2d03fa2684312887ab93c3c9a0b080021b468f53b`;
  256 inputs, 512 outputs, 331113 wires, 54868 AND, 269622 XOR, 6367 INV,
  330857 gates, full depth 10675, AND depth 3301, 2979847 encoded bytes, and
  1755776 estimated Half-Gates table bytes. Its schedule uses 4737 reusable
  slots and 2317081 bytes, with digest
  `0d7c79a0ab31b2ae04b91319355bb79aef32c5f3d5f8532a3db632b121f627da`.
- Provisional activation (`0x91`): digest
  `747fa6f1815e3a0c70f0077ffc10508882f321ad6e7bb422f4eef695a853b5a5`;
  2048 inputs, 512 outputs, 369288 wires, 62716 AND, 294021 XOR, 10503 INV,
  367240 gates, full depth 17903, AND depth 5723, 3307294 encoded bytes, and
  2006912 estimated table bytes. Its schedule uses 5761 reusable slots and
  2571762 bytes, with digest
  `e0f9dfb3f3b85eab28fbab81788e0efea25dac7c8de207af8ce9e57567c6ad25`.
- Provisional export (`0x92`): digest
  `3cc95694e01966642db7eaed9d68a4116c66bc4d72f14908d0d3b5e25ee79838`;
  1024 inputs, 256 outputs, 5608 wires, 765 AND, 3819 XOR, no inversions,
  4584 gates, full depth 766, AND depth 255, 42366 encoded bytes, and 24480
  estimated table bytes. Its schedule uses 1025 reusable slots and 32658
  bytes, with digest
  `bb4b0b1de87baa1bf7b190c8c57538a67367091483a4cb08abc1a2392f55b071`.

Each `EYAOSC01` schedule binds the component tag and canonical IR digest. The
generator pins ordered outputs, releases operands at their last use, reads a
gate's inputs before writing its output, and assigns the smallest free slot.
All three schedules use two-byte slot identifiers and seven-byte gate records.
The public-synthetic clear evaluators execute these schedules.

At one 16-byte label per slot, the activation high-water count implies 92176
bytes. This is a provisional single-label storage calculation. Production may
need multiple label or slot buffers, and this figure excludes tables, protocol
material, framing, and allocator overhead.

Variable-time clear evaluators accept only public synthetic inputs. Tests cover
the IR, add/clamp/scalar fragments, every noncanonical `tau` field, all five
committed arithmetic cases, and 128 deterministic differential cases through
both provisional cores. They freeze all three canonical IR encodings, all three
liveness schedules, six purpose-specific digests, tags, schemas, metrics,
padding words, dead-gate pruning, and scheduled/unscheduled parity.

These components, schedules, and generated bundle are benchmark-only and
non-promotable. Independent artifact byte decoding/evaluation, garbling, OT,
private-output translation, protocol entrypoints, constant-time claims, P0-P3
security claims, Phase 2B benchmark identities, and Phase 6B production
artifacts remain separate work.

Run the focused checks with:

```sh
cargo test --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  circuit::
```

### Generated Phase 2A artifact bundle

The `ed25519-yao-circuit-artifacts` executable deterministically emits six
binary files plus `ed25519-yao-phase2a-bundle-v1.bin`:

| Tag | File |
| --: | ---- |
| `1` | `sha512-fixed32.ir.bin` |
| `2` | `sha512-fixed32.schedule.bin` |
| `3` | `activation.ir.bin` |
| `4` | `activation.schedule.bin` |
| `5` | `export.ir.bin` |
| `6` | `export.schedule.bin` |

The canonical index begins with `EYAOBA01` and entry count six. Each ordered
entry encodes its one-byte tag, BE16 filename length, UTF-8 filename, BE64 file
length, and SHA-256 file digest. The index is 387 bytes with digest
`aa62b83b38163bf898c90084f2eb25df1c95ba41274d0f7826250f9168b80db1`.

Emit and check the intentionally uncommitted bundle with:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-circuit-artifacts -- emit \
  --output-dir target/ed25519-yao-phase2a-bundle-v1

cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-circuit-artifacts -- check \
  --input-dir target/ed25519-yao-phase2a-bundle-v1
```

Artifact filesystem I/O supports Linux and macOS. Paths must be normalized,
must have an existing protected parent, and may contain no symlinked component.
Every directory component must be owned by the effective user or root; shared
write permission on an ancestor additionally requires the sticky bit. An
existing bundle directory and all seven files must also be owned by the
effective user or root and grant no group or other write permission. Emission
builds all seven files through no-follow descriptors in a private same-parent
staging directory, syncs them, and publishes the directory with an atomic
no-replace rename. A destination must be absent or already contain the exact
bundle; empty and mismatching destinations are left unchanged. The checker
recompiles the canonical bytes and uses descriptor-relative bounded reads. It
requires exactly those seven single-link regular files and rejects missing,
extra, oversized, hardlinked, symlinked, concurrently changed, or mutated
entries. Every opened descriptor must also satisfy the normative
[`artifact-filesystem-policy-v1.md`](docs/artifact-filesystem-policy-v1.md):
macOS requires `MNT_LOCAL` and rejects authority-expanding allow ACL entries,
while Linux accepts only its closed local-filesystem allowlist and rejects known
ACL xattrs. Deny-only macOS ACLs are accepted because they add no authority. Remote,
OverlayFS, FUSE, and unknown filesystems fail closed. The descriptor-only
macOS ABI wrapper is isolated in `artifact-fs-policy`; this generator retains
`#![forbid(unsafe_code)]`. It does not decode or evaluate directory-supplied bytes. The index is
a Phase 2A reproducibility index and has no Phase 2B or production-manifest
authority.

The bundle module has eleven focused tests covering index goldens, atomic and
idempotent publication, no-repair mismatch behavior, stale staging siblings,
missing/extra/oversized entries, root and ancestor symlinks, expected-file
symlinks and hardlinks, nondirectory targets, unsafe shared parents and
ancestors, unsafe bundle/file modes, root-owner policy, and parent-component
rejection. The counted policy crate adds three platform-stable tests for the
local-filesystem classifier, ACL rejection, and the current temporary
filesystem. Its macOS test accepts a real deny-only ACL and rejects a real allow
ACL.

`benchmark_manifest` wraps this exact index in a separate benchmark-only
`EYAOBM01` Phase 2B candidate. Its 1973-byte canonical encoding has digest
`c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81`
and binds the compiler contract, explicit bit/wire order, schemas, all IR and
schedule identities and metrics, plus the passive `32*AND` table estimate. The
builder accepts no caller artifacts; the strict parser accepts only exact
compiler regeneration. Six tests cover its frozen identity and rejection
boundary. Inspect it with:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-benchmark-manifest -- summary
```

This candidate has no conversion into a production manifest. The stdlib-Python
verifier independently decodes it and cross-checks the wrapped bundle index.
The strict `phase2b-core-reconciliation-v1` certificate now binds this candidate
to all twenty Phase 1 corpora, exact input/output mappings, separate IR and
schedule evaluation, coherent party-output reconstruction, and activation's
zero-evaluation continuation. The counted `cargo yao-fv
phase2b-reconciliation-check` gate passes. Independent-host reproduction and
reviewer approval remain Phase 2B gates.

The filesystem policy has no runtime override. Adding a filesystem or ACL
representation requires a reviewed normative change and counted tests.

The contribution KDF uses HKDF-SHA256 with frozen extract/expand domains and
fixed A/B, client/server, and `y`/`tau` tags. Its expand info ends with the
stable-context binding digest. A single synthetic client root produces the two
role-separated client contributions; separate synthetic A and B roots each
produce only their own server contribution. The committed
`vectors/ed25519-yao-kdf-v1.json` corpus records the three public synthetic
roots, all eight derived contributions, and the resulting public identity.

Regenerate or check the KDF-continuity corpus with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-kdf \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-kdf \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json
```

## Host-only output sharing

`output_sharing` accepts explicit public fixture coins and returns typed,
nonserializable role/recipient shares. Registration, recovery, and refresh
share `x_client_base` and `x_server_base` modulo `l`. Authorized export shares
the RFC 8032 seed modulo `2^256`. Separate activation and export APIs make seed
shares representable only for export; separate client and SigningWorker coin
and share types reject role or recipient swaps at compile time.

`docs/output-sharing-v1.md` freezes the exact arithmetic and the strict
six-case corpus. Its source inputs are copied into each case so an independent
implementation can recompute the joined values without loading another vector
file. The corpus DTO is opaque and `Serialize`-only; its exact byte parser
accepts only the canonical pretty JSON with one trailing LF. The host-only
reference contains no random generator, wire encoding, private output
translation, authentication, encryption, or deployable API.

Regenerate or check the output-sharing corpus with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-output-sharing \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-output-sharing-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-output-sharing \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-output-sharing-v1.json
```

## Host-only registration reference

`registration_reference` closes the deterministic arithmetic portion of
registration over three purpose-typed public synthetic roots and one stable
context. Preparation derives the A-client, B-client, A-server, and B-server
`y`/`tau` contribution pairs internally, constructs the typed A/B inputs, and
evaluates only the seed-free activation family. Independent tests reproduce the
HKDF expand inputs and outputs plus the Ed25519 arithmetic and public-key
relation.

`evaluate_host_only_registration_output_sharing_v1` consumes one preparation
and explicit fixture coins, then returns only typed client and SigningWorker
scalar shares. Its result cannot represent an export seed share. Six focused
tests cover exact KDF domains, root/context separation, deterministic borrowed
inputs, full activation arithmetic, zero/small/boundary coins, role-swap type
rejection, and seed-access rejection.

This variable-time reference handles public synthetic fixtures only. It does
not establish admission, production root custody, authenticated input opening,
selected-profile input selection or active anti-bias, recipient encryption,
durable persistence, or protocol security by itself. The separate registration
evaluator-admission composition supplies the complete construction-independent
host evaluator. The lifecycle-continuity registration case remains a separate
zero-work metadata snapshot.

## Host-only registration evaluator admission

`registration_evaluation_admission` seals the exact registration ceremony,
authorization intent, ordered provenance pair, both opaque input-selection
evidence identities, checked-at time, first activation epoch, one-use execution,
and terminal selection attempt before the artifact session begins. The session
consumes this move-only capability, enforces the admitted stable KDF scope, runs
one activation-family evaluation, and binds the admission digest into every
package and the output-committed receipt.

Success creates one move-owned candidate state containing the established
Ed25519 public key and exact committed-receipt identity. The typed admission
fields and terminal selection survive pending activation, metadata consumption,
and verified SigningWorker activation. Evaluator failure burns the request and
execution while retaining the same terminal selection and the public
`Unregistered -> Unregistered` state class.

Eight core tests, five strict corpus tests, seven independent Python tests, and
twelve Lean theorems cover this ideal host relation. The public identity scope
is not an authenticated absence proof. Durable uniqueness and retry
coordination, production input-opening verification, selected-profile security,
production storage/promotion, and production constant-time execution remain
Phase 6B-7 obligations. See `docs/registration-evaluator-admission-v1.md`.

## Host-only recovery reference

`recovery_reference` implements the narrow arithmetic portion of same-root
recovery over borrowed public synthetic inputs. Preparation requires the
recovered client root to equal the current root, re-derives both role-separated
client contributions under the unchanged stable context, verifies every current
client `y` and `tau` contribution, and preserves the validated server fields.
It then checks joined `d`, SHA-512, clamp output, `a`, `tau`, both scalar bases,
both points, and `A_pub` byte for byte across the current and recovered
activation evaluations. The lifecycle-continuity recovery fixture uses this as
its sole arithmetic implementation.

`evaluate_host_only_recovery_output_sharing_v1` composes a validated preparation
with explicit fixture coins and the typed activation output-sharing API. Its
result can carry only client and SigningWorker scalar shares. Recovery cannot
represent an export seed share.

This reference performs variable-time equality and arithmetic over public
synthetic fixtures. It does not authenticate registered state, consume an
authorization, open or replace a protected credential envelope, generate
packages or receipts, persist a transition, implement cutover, or provide the
complete `evaluate_recovery_v1` contract. Production code cannot depend on this
crate.

## Host-only recovery evaluator admission

`recovery_evaluation_admission` composes the narrow recovery arithmetic with one
sealed construction-independent admission. It binds the exact recovery ceremony,
ordered A/B provenance pair, strictly verified old-state resolution, checked-at
time, distinct replacement credential, same-root artifact identity, selected-
mechanism acceptance identity, advancing activation epoch, and one-use execution.
Admission suspends the old credential before the single evaluation begins. The
admission digest is the sole semantic evaluation evidence accepted by the
recovery session.

The move-only `TerminalRecoveryEvaluationV1` survives output commitment,
metadata consumption, recipient release, verified recovery-origin SigningWorker
activation, and promotion. Evaluator abort burns the request and execution while
retaining the same terminal authority and credential-suspended state. Output
commitment checks the request, authorization, transcript, activation epoch,
execution identity, admission digest, and registered Ed25519 key before creating
the pending recovery value.

The tranche contains eight core tests and five strict corpus tests. Its
independent verifier and structural Lean model each target seven tests and twelve
theorems. Aggregate gate integration is tracked separately. The same-root
artifact and selected-mechanism digest are distinct opaque evidence identities;
this host layer does not prove their relation. Production private-input opening,
root custody, durable suspension/replay/atomicity, transport, constant-time
execution, and every P0-P3 security property remain later obligations. See
`docs/recovery-evaluator-admission-v1.md`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-recovery-evaluator-admission \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-recovery-evaluator-admission-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-recovery-evaluator-admission \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-recovery-evaluator-admission-v1.json
```

## Host-only refresh reference

`refresh_reference` takes move ownership of distinct A/B ideal fixture
contributions and derives their nonzero modular joint delta internally. It
preserves all client contribution bytes and checks the exact
`+delta_y`/`+delta_tau` update for Deriver A and the exact inverse update for
Deriver B, then checks joined `d`, SHA-512, clamp output, `a`, `tau`, both scalar
bases, both points, and `A_pub` byte for byte. The lifecycle-continuity refresh
fixture uses this preparation as its sole arithmetic path. The corpus records
both role contributions and their independently checked combined fields.

`evaluate_host_only_refresh_output_sharing_v1` consumes the prepared state and
shares only the refreshed activation scalar outputs for the client and
SigningWorker. Its result has no seed family.

The input contributions are public synthetic material and every comparison is host-only
variable-time evidence. This reference does not authenticate roots, KDF
provenance, registered state, or epochs; generate or prove a joint unbiased
delta; process authorization; create packages or receipts; persist output
commitment; perform cutover or rollback recovery; or provide the complete
`evaluate_refresh_v1` contract.

The fallible preparation is a defensive self-check around the typed transform,
not an independent proof system. Independent test arithmetic covers ordinary,
carry/borrow, and scalar-wrap cases.

## Host-only refresh evaluator admission

`refresh_evaluation_admission` composes the narrow refresh arithmetic with one
sealed construction-independent admission. It binds the exact refresh ceremony,
ordered A/B provenance pair, strictly verified current-state resolution,
checked-at time, complete current and proposed A/B role-state bindings, the
provenance continuity-artifact identity, a separate selected-mechanism acceptance
identity, advancing activation and role epochs, and one-use execution. The
admission digest is the sole semantic evaluation evidence accepted by the
refresh session.

The move-only `TerminalRefreshEvaluationV1` retains the unchanged authenticated
current state and exact proposed next bindings through output commitment,
metadata consumption, recipient release, verified refresh-origin SigningWorker
activation, and promotion. Evaluator abort burns the request and execution,
preserves the registered-state self-loop, and leaves the proposal non-promotable.
Output commitment checks the request, authorization, transcript, activation
epoch, execution identity, admission digest, and registered Ed25519 key before
creating the pending refresh value.

Eight core tests, five strict corpus tests, seven independent Python tests, and
twelve Lean theorems cover this host relation. The continuity artifact and
selected-mechanism digest remain distinct opaque evidence identities. This layer
does not prove production private-input opening, delta entropy or independence,
anti-bias, selective-abort or retry-grinding resistance, forward security,
mobile-adversary healing, secure erasure, durable replay/atomicity/retirement,
transport, constant-time execution, or any P0-P3 security property. See
`docs/refresh-evaluator-admission-v1.md`.

The construction-independent semantic-frame attachment freezes eleven directed
frame classes, eleven delivery states, seven closed consuming role views, ten
static corruption markers, and four uninstantiated real/ideal interface shapes.
Its strict eight-case corpus covers registration, recovery, and refresh through
receipt-verified worker activation, export release and exact redelivery, and all
four evaluator-abort branches. Every step records cumulative value learning,
frame observation, public identity labels, and retry/redelivery policy. Runtime
frame bytes, transport, durable coordination, selected-profile security, a
simulator implementation, production serialization, constant-time execution,
and erasure remain outside this host-only layer. See
`docs/semantic-frame-party-views-v1.md`.

The Phase 2B reconciliation attachment advances the audited evidence baseline
to 26 reference specifications, 21 committed corpora, 418 generator Rust tests,
186 independent Python tests, and 158 Lean theorems. Its counted gate passes six
focused Rust tests, four focused Python tests, and independent verification of
all five request kinds.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-refresh-evaluator-admission \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-refresh-evaluator-admission-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-refresh-evaluator-admission \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-refresh-evaluator-admission-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-semantic-frame-party-views \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-frame-party-views-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-semantic-frame-party-views \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-frame-party-views-v1.json
```

## Host-only export reference

`export_reference` composes the synthetic export projection with the required
registered-public-key equality check before seed sharing. Preparation borrows
validated A/B contribution tuples and a caller-supplied canonical registered
key, evaluates the export oracle, and rejects an exact key mismatch. The
prepared type privately owns the joined export output and exposes only the
expected key and a host-only equality witness; it has no seed or oracle-material
getter.

`evaluate_host_only_export_output_sharing_v1` consumes that preparation and one
explicit fixture coin. The joined output is dropped, and the success value
contains only the expected key, equality witness, and typed Deriver A/B export
shares. Reconstructing the seed remains an explicit export-only host helper.

The narrow arithmetic helper accepts an expected key. The lifecycle composition
places it behind authenticated registered-state resolution, canonical ceremony
validation, and branch-typed A/B provenance. Rust move consumption remains
call-local ownership evidence. This variable-time public-synthetic reference
makes no unbiased-randomness, recipient-encryption, durable persistence,
zeroization, constant-time, or selected-profile security claim.

## Host-only export evaluator authorization

`export_evaluation_acceptance` requires separately verified, role-pinned
Deriver A and Deriver B acceptances before the export artifact session can
begin. Each strict Ed25519 signature binds the exact request and authorization
digests, replay nonce and expiry, Client recipient key, authenticated registered
state and key, ordered provenance pair, role-local provenance statement,
one-use execution ID, and the role's trusted authority identity. Export
issuance owns the trusted A/B authority pair, so coherently re-signing under
caller-substituted keys cannot authorize evaluation.

The ordered acceptance-pair digest becomes the export evaluation-evidence
digest and is retained through output commitment and Client release. Session
admission consumes the move-only pair. Seven core tests cover success, expiry,
signature failure, role-key reuse at both authority and verified-pair boundaries, coherent
authority substitution, execution splicing, and invalid admission time. The
strict one-case corpus is independently reconstructed by Rust and Python and is
modeled by twelve Lean structural theorems; one compile-fail guard pins linear
pair consumption.

The authorization-record digest remains an opaque boundary value. Policy,
actor, step-up-authentication, scope, revocation, and approval claims must be
validated before the Derivers sign. Production authority distribution,
transport, durable replay, recipient encryption, constant-time execution, and
P0-P3 protocol security remain outside this host-reference claim. See
`docs/export-evaluator-authorization-v1.md`.

## Host-only semantic package and receipt bodies

`semantic_artifacts` derives its input-provenance digest only from a validated
A/B provenance pair whose request kind, request-context digest, authorization
digest, and transcript digest match the exact ceremony DAG. Registration,
recovery, refresh, and export use separate move-only ceremony-bound evaluation
contexts. Their only package-producing methods consume the context, narrow
branch-specific host-reference inputs, explicit fixture coins, and typed opaque
bindings; they run preparation, evaluation, output sharing, and package
construction in one call. No package constructor accepts an independently
precomputed host-reference success. Export derives its expected registered key
exclusively from the authorization- and provenance-bound context.

Activation-family package construction permits a zero individual A/B additive
scalar share and its identity point commitment. It rejects identity after the A/B
shares are joined into the client or SigningWorker signing point. Registration
derives the candidate registered key from those joined points; recovery and
refresh compare it with the provenance-bound registered key. Activation-client
and export-client opaque binding types are disjoint.

The remaining recipient-protection, ciphertext, output-binding, package-
authentication, evaluation-evidence, receipt-evidence, and authorization-
consumption digests are profile-neutral slots. They authenticate nothing in this
host reference and carry no cipher, proof, signature, persistence, constant-time,
or P0-P3 security claim. The move-only evaluator closes call-local type-level
ceremony/evaluation mixing only. Opaque provenance and evidence do not
authenticate the supplied synthetic inputs.

## Versioned fixed reference

`docs/fixed-reference-v1.md` owns the implemented reference encodings,
arithmetic relations, contribution KDF, proof-system-neutral provenance outer
bytes, host-only output-sharing arithmetic, and corpus commitments. One
generated region carries the exact
identifiers, constants, golden bytes, KDF rows, corpus hashes, and exact byte
commitments for the output-sharing, circuit-IR, ceremony-context,
input-provenance, semantic-artifact lifecycle, and output-party-view companion
specifications, plus the evaluation-input party-view companion specification.
Check it with:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-spec-goldens -- check \
  --input tools/ed25519-yao-generator/docs/fixed-reference-v1.md
```

After an intentional implementation change, regenerate that region in place
and review the resulting specification diff:

```sh
cargo run --locked \
  --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-spec-goldens -- render \
  --template tools/ed25519-yao-generator/docs/fixed-reference-v1.md \
  --output tools/ed25519-yao-generator/docs/fixed-reference-v1.md
```

`docs/circuit-ir-v1.md` separately owns the Phase 2A Boolean IR, fixed
SHA-512/32 component, provisional activation/export cores, deterministic
liveness schedules, generated six-file bundle, canonical index, and benchmark
goldens. Their component, schedule, file, and bundle identities cannot be used
as Phase 2B or production artifact identities.

`joint_refresh_delta` validates distinct host-only A/B fixture contributions
and derives their nonzero modular sum. `lifecycle_reference` supplies only the
opposite-update transform used by `refresh_reference`. A refresh can
apply a nonzero `delta_y` to A and its modular negative to B, plus a nonzero
canonical `delta_tau` and its scalar negative, while preserving joined `y`,
joined `tau`, `d`, `a`, both scalar bases, both points, and the public key. This
module accepts public fixtures only. It does not implement production delta
generation, commitment proofs, package delivery, persistence, or active
security.

## Host-only lifecycle evidence

`lifecycle_domain` is a nonserializable host-only ownership layer. Canonical
registration, recovery, refresh, and export requests own their complete ceremony
DAGs. `RegisteredLifecyclePreStateV1` is a crate-private raw projection of one
store-resolved registered key, active credential binding, stable scope,
root/state-record bindings, and epochs. `authenticated_store` signs its
request-bound canonical resolution with
a non-weak epoch-bound Ed25519 authority key and exposes only a move-only
strictly verified wrapper to registered issuance. The signature covers the
active state version and activation epoch, durable identity, exact ceremony
digests, ordered provenance-pair digest, and every registered-state field.
Crate-private
`RoleInputProvenancePairV1` bridges expose the matching registered recovery,
refresh, or export state only to this lifecycle integration. They compare every
projected state field before evaluation, including refresh current/next role
epochs and the authorization epochs.

Recovery session construction derives a sealed authenticated credential-
continuity value from the signed active credential and state version, the
distinct replacement credential fixed by authorization, and the common A/B
same-root evidence artifact fixed by provenance. It is retained through output
commitment and metadata consumption. Production custody and proof verification
remain a release gate.

Registration, recovery, refresh, and export artifact issuance and semantic
sessions are crate-private and move-owned. Recovery and refresh issuance require
strictly advancing activation or role-input-state epochs, while rejected
issuance returns every owned input. A session-binding rejection returns the
request and issuance before evaluation. If evaluation fails after admission, it
returns a non-callable `BurnedArtifactAttemptV1` and, for registered branches,
the unchanged authenticated store resolution, without returning a reusable
request. Successful activation-family evaluation seals the origin request in an
origin-typed `PendingActivationPreStateV1` with committed packages and receipt
evidence. Export seals it in a committed export value retaining the unchanged
registered projection.

The exact contract is frozen in
`docs/authenticated-store-resolution-v1.md`. Production record parsing,
rollback floors, authority-key distribution, and atomic durable transactions
remain outside this host evidence.

Activation control is also crate-private. It derives a fresh canonical
activation DAG from `ActivationControlFreshFieldsV1` and the output-committed
origin, rejects non-distinct attempts with one redacted
`UniformLifecycleAbortV1`, and retains the exact pending value for retry.
`consume_activation_metadata_v1` moves accepted control metadata into
`MetadataConsumedActivationStateV1` and records a `ZeroReevaluationWitnessV1`.
It does not open a recipient package, invoke either Deriver, resample outputs,
activate a SigningWorker, or promote registration, recovery, or refresh state.

`lifecycle_persistence` exposes three construction-independent, nonserializable
digest-only views: `OutputCommittedActivationProjectionV1`, an
`AttemptRejectedActivationProjectionV1` whose before and after values are
identical, and `MetadataConsumedActivationProjectionV1`. Their enclosing
`ActivationPersistenceProjectionV1` is a persistence-state scaffold. It does
not serialize or durably store records.

`lifecycle_fixtures` is a separate strict JSON evidence surface. Its six cases
cover a synthetic public registration-candidate metadata snapshot, first
activation, same-root recovery, recovery-origin activation, opposite-delta
refresh, and refresh-origin activation. The refresh case changes role-local
`y_A`, `y_B`, `tau_A`, and `tau_B` by exact opposite deltas while preserving
joined and downstream identity fields. The registration snapshot records zero
represented work and makes no registration-evaluator claim. The activation
cases contain ideal activated snapshots and reference counters only; they do not
claim that `lifecycle_domain` promotes durable state.

Regenerate or check the lifecycle-continuity corpus with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-lifecycle-continuity \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-lifecycle-continuity-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-lifecycle-continuity \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-lifecycle-continuity-v1.json
```

`semantic_lifecycle_fixtures` owns a separate strict five-branch public corpus.
Registration, recovery, and refresh carry their exact four descriptor
encodings, activation package set and digest, output-committed receipt body and
digest, and output-committed persistence identity. Export carries its two
client-only descriptors, package set, released receipt linked to its preceding
output commitment, and the closed `registered_state_retained` effect. Activation cross-links all three valid
origins to fresh metadata-consumed ceremonies with five zero counters and four
reconstructed freshness-reuse rejections whose persistence is an exact
self-loop.

The independent Python verifier parses every LP32 layer, recomputes typed
digests and recipient bindings, cross-links the ceremony and provenance
attachments, adds A/B public share points, checks prime-subgroup membership and
`2*X_client-X_server=A_pub`, reconstructs rejected attempts from their public
fresh fields, and recursively rejects secret-bearing fields. The corpus carries
no root, contribution, scalar or seed share, output coin, ciphertext, recovery
credential, refresh delta, or Yao protocol material. Its complete contract is
`docs/semantic-artifact-lifecycle-v1.md`.

Regenerate or check the semantic-lifecycle corpus with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-semantic-lifecycle \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-semantic-lifecycle \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json
```

`output_party_views` composes typed output shares with full committed semantic
artifacts into consuming, role-specific custody views. Activation-family
builders validate all four descriptor share points, both reconstructed public
points, and `2*X_client-X_server=A_pub`. Export consumes the released transition,
extracts the exact A/B shares retained from its evaluation, and validates the
reconstructed RFC 8032 seed against the registered key. Separate consuming A and B
methods prevent one validated set from projecting both Deriver views. Router,
Observer, Diagnostics, package-prepared SigningWorker, and metadata-consumed
extensions are structurally empty.

The strict five-case output-party-view corpus cross-links those views to the
semantic-lifecycle attachment. It contains synthetic A/B role shares and the
authorized Client output only at their exact role paths. It is test evidence,
not public runtime leakage. The corpus contains no roots, contributions, output
coins, joined SigningWorker scalar, refresh delta, credential, ciphertext bytes,
OT, garbling, label, or mask material. Its normative contract is
`docs/output-party-views-v1.md`.

Regenerate or check it with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-output-party-views \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-output-party-views \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json
```

`export_delivery` owns the construction-independent transition from export
output commitment to Client release. Output commitment retains exact packages
and shares while leaving authorization unconsumed. Delivery uncertainty keeps
that identity available for retry. Release consumes authorization and binds
Client-delivery evidence to the preceding receipt. Redelivery preserves the
released receipt and seed with zero private reevaluation. Its strict one-case
corpus and normative contract are
`vectors/ed25519-yao-export-delivery-v1.json` and
`docs/export-delivery-lifecycle-v1.md`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-export-delivery \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-export-delivery-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-export-delivery \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-export-delivery-v1.json
```

`activation_delivery` owns the construction-independent transition from an
activation-family output commitment through admitted control, metadata
consumption, delivery uncertainty, and atomic Client/SigningWorker recipient
release. Authorization advances from not issued to unconsumed to consumed and
never regresses. Release reconstructs the Client scalar only inside its
release capability while the SigningWorker receives a disjoint activation
authority retaining the exact same-evaluation worker shares. Redelivery is an
exact released-state identity self-loop with zero private work. The strict
registration/recovery/refresh corpus cross-links the semantic-lifecycle and
output-party-view corpora and contains no worker scalar, A/B share, opener,
ciphertext, or protocol-frame material. Its normative contract is
`docs/activation-delivery-lifecycle-v1.md`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-activation-delivery \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-activation-delivery-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-activation-delivery \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-activation-delivery-v1.json
```

`activation_recipient_party_views` starts after that release transition and
keeps the frozen five-stage output-party-view family unchanged. Its two closed
host stages project the atomic Client scalar/SigningWorker authority split and
the later receipt-verified SigningWorker activation across seven roles. The
Client retains only its release capability; the SigningWorker authority remains
opaque before activation and becomes a sealed activated-state view afterwards.
Deriver and infrastructure extensions stay empty. The Rust activated state has
no scalar accessor. The strict three-origin DTO includes one synthetic
`x_server_base_hex` solely inside the activated SigningWorker extension so the
independent verifier can reconstruct it from the companion A/B shares and
validate the public point, registered key, exact activation receipt, key
binding, and strict signature. Frames and durable records are absent. The
normative contract is `docs/activation-recipient-party-views-v1.md`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-activation-recipient-party-views \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-activation-recipient-party-views-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-activation-recipient-party-views \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-activation-recipient-party-views-v1.json
```

The recovery credential-transition corpus continues the recovery recipient
case through credential promotion. It freezes old-credential suspension,
verified recovery-origin worker activation, complete registered-state
preservation, replacement activation, old-version tombstoning, and the exact
store-authority-signed promotion receipt. The store authority is inherited from
the authenticated old-state resolution. The independent verifier pins that
authority and rejects coherent attacker-key re-signing. Its normative contract
is `docs/recovery-credential-transition-v1.md`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-recovery-credential-transition \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-recovery-credential-transition-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-recovery-credential-transition \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-recovery-credential-transition-v1.json
```

`evaluation_input_views` projects the accepted-evaluation boundary before any
runtime protocol frame exists. Registration, recovery, and refresh expose only
each Deriver's four purpose-typed `y`/`tau` inputs. Export exposes only each
Deriver's two `y` inputs. Activation is a zero-work continuation with no private
evaluation input. Client, SigningWorker, Router, Observer, and Diagnostics
extensions are structurally empty. Separate branch-specific host-only ideal-
coin wrappers supply two scalar-sharing coins, no activation coin, or one
export seed-sharing coin; those values never enter a party view.

The strict five-case corpus cross-links ceremony, provenance, semantic-
lifecycle, and output-party-view companions. It independently demonstrates
recovery input equality, exact opposite refresh server deltas, y-only export,
zero-work activation, output-share reproduction from the explicit fixture
coins, and static consuming A/B observations. The synthetic inputs and coins
are verifier evidence rather than runtime public leakage or a production wire
format. Its complete contract is `docs/evaluation-input-party-views-v1.md`.

Regenerate or check it with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-evaluation-input-party-views \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-evaluation-input-party-views-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-evaluation-input-party-views \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-evaluation-input-party-views-v1.json
```

`UniformLifecycleAbortV1` is the exact four-field public envelope frozen by
`docs/uniform-abort-envelope-v1.md`. It derives request kind and public
transcript digest from a sealed ceremony DAG, uses one redacted host-reference
failure code, and has one `aborted` terminal state. It contains no request-
context digest, authorization detail, Deriver blame, peer frame, or private
payload. The strict five-case corpus links all request kinds to the independently
verified ceremony-context corpus.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-uniform-abort \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-uniform-abort-envelope-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-uniform-abort \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-uniform-abort-envelope-v1.json
```

Activation-metadata rejection and every admitted registration, recovery,
refresh, or export host-reference evaluation failure expose this envelope.
Evaluator failures retain their detailed semantic cause only behind a crate-
private accessor, and their `Debug` output is redacted to the public abort.
Selected-profile protocol failure integration, production bytes, frame/ticket
handling, timing equivalence, selective-failure resistance, and selected-
profile correctness-with-abort remain open.

`EvaluationAbortedPersistenceProjectionV1` models admitted pre-output evaluator
failure with branch-specific retention types. Registration remains
unregistered; recovery, refresh, and export expose exact registered-state
self-loops. `HostOnlyEvaluatorAbortPartyViewSetV1` projects only the uniform
abort to each of seven consuming role observations. The strict four-case corpus
is specified by `docs/evaluator-abort-state-party-views-v1.md` and lives at
`vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json`.

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-evaluator-abort-views \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-evaluator-abort-state-party-views-v1.json
```

Complete activation recipient delivery and the remaining lifecycle evaluator
surfaces; complete runtime frame/delivery views and corruption-game interfaces; authenticated
ciphertext/package processing;
durable records and transactions; replay storage; selected-
profile package opening; production registered-identity/state-version promotion;
recovery credential/root custody; and atomic refresh cutover
stay outside this slice.

## Host-only provenance outer contract

`provenance` implements sealed A/B role types, branch-specific registration,
recovery, refresh, and export statements, fixed LP32 encoders, strict
structural decoders, nonzero role-typed epochs, registered Ed25519 point
validation, and an ordered statement pair. `provenance_fixtures` commits one A/B
case per valid evaluation request kind plus all eight generic artifact-wrapper
goldens. Activation has no statement variant.

The independent Python verifier reproduces stable-context bindings, wrapper,
envelope-set, statement, and pair digests; checks nested encodings and fixed
A-then-B ordering; validates refresh epoch continuity; validates registered
points and prime-subgroup membership; and cross-links every provenance case to
the independently reconstructed request, authorization, and transcript digests
in the ceremony-context corpus. Artifact and record digest slots contain public
synthetic test values. This surface supplies canonical host-only bytes. It
contains no production commitment, proof, root custody, anti-bias mechanism,
authenticated authorization record, replay enforcement, or transport binding.

Regenerate or check the provenance corpus with:

```sh
cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- emit-provenance \
  --output tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json

cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml \
  --bin ed25519-yao-vectors -- check-provenance \
  --input tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json
```

The five-case arithmetic corpus continues to record caller-supplied synthetic
contributions. The KDF continuity corpus connects the frozen context and roots
to the same oracle in a separate strict schema. The normative provenance and
epoch contract is specified in `docs/input-provenance-v1.md`. Production
custody and profile-required artifacts, the selected registration
input-selection contract, refresh-delta generation, executable party views,
distributed cutover, and selected-protocol semantics remain Phase 1 work. The
lifecycle boundary is specified in
`docs/ideal-functionalities-v1.md`; its explicit blockers prevent the fixture
corpus from being mistaken for a complete lifecycle model.

This crate must never be linked into a production Worker or exposed as a
protocol API. It contains no message formats, network handlers, persistence,
or production negotiation surface. A `wasm32` build is rejected at compile
time.

Only synthetic inputs and published test-vector material are allowed. These
host-only reference types do not promise zeroization. Real wallet seeds,
derivation contributions, scalar shares, or other production secrets are
forbidden.

Run its checks directly:

```sh
cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml
```

# Independent Ed25519 Yao Vector Verifier

This directory contains a Python 3 standard-library implementation of the
Ed25519 Yao v1 clear arithmetic. It imports no Rust package, generated module,
workspace JavaScript dependency, or third-party Python package.

The arithmetic verifier accepts any nonempty, strictly shaped v1 arithmetic
corpus. Schema auto-detection also handles the fixed auxiliary corpora. It
independently checks stable-context encoding and binding, split seed and scalar
arithmetic, SHA-512 and RFC 8032 clamping, scalar reduction, Edwards25519
base-point multiplication and compression, public keys, and the export-only
seed result.

`verify_artifacts.py` is a separate strict consumer of the provisional Phase 2A
bundle. It requires the exact seven-file directory and `EYAOBA01` index, parses
the `EYAOIR01` and `EYAOSC01` formats without Rust code, rederives last uses and
the smallest-free schedule, requires byte-for-byte schedule equality, evaluates
both representations, and reproduces SHA, activation, and export outputs for
the five committed cases. On Linux and macOS it walks every directory component
through no-follow descriptors, enumerates the held directory twice, and opens
each fixed file relative to that descriptor. Exact-size bounded reads require a
single-link regular inode whose metadata remains stable. Root, ancestor, and
entry symlinks, hardlinks, oversized files, and path replacements are rejected
without following them.

Run it from the repository root:

```sh
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-lifecycle-continuity-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-output-sharing-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json \
  --semantic-lifecycle-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-activation-delivery-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json \
  --semantic-lifecycle-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --output-party-view-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-activation-recipient-party-views-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json \
  --semantic-lifecycle-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --output-party-view-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json \
  --activation-delivery-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-activation-delivery-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-recovery-credential-transition-v1.json \
  --ceremony-context-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json \
  --semantic-lifecycle-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --output-party-view-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json \
  --activation-delivery-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-activation-delivery-v1.json \
  --activation-recipient-party-view-corpus tools/ed25519-yao-generator/vectors/ed25519-yao-activation-recipient-party-views-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-evaluation-input-party-views-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json \
  --provenance-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-provenance-v1.json \
  --semantic-lifecycle-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-semantic-lifecycle-v1.json \
  --output-party-view-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-output-party-views-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-uniform-abort-envelope-v1.json \
  --ceremony-context-corpus \
  tools/ed25519-yao-generator/vectors/ed25519-yao-ceremony-context-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  /tmp/ed25519-yao-differential-v1.json \
  --differential-seed-hex \
  5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
python3 -m unittest discover \
  -s tools/ed25519-yao-verifier -p 'test_*.py'
```

After emitting a bundle, run the artifact verifier with:

```sh
python3 tools/ed25519-yao-verifier/verify_artifacts.py \
  /tmp/ed25519-yao-phase2a-artifacts \
  tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json
```

The optional differential seed makes the verifier independently regenerate
the SHA-512-expanded inputs, scalar reductions, context digest, participant
identifiers, request-kind cycle, and exact case identifier for each index.
Schema auto-detection also verifies the KDF continuity corpus with a standalone
application-binding encoder, SHA-256 digest, HMAC/HKDF-SHA256 implementation,
frozen role/source/output tags, all eight contributions, and the complete
joined Ed25519 trace. It checks that the four immutable binding facts produce
the digest consumed by the stable context before reproducing the KDF. The
binding facts are wallet identity, Ed25519 signing-key identity, logical
signing-root identity, and the immutable positive key-creation signer slot. It
independently enforces the version-one identifier grammar of one or more visible
ASCII bytes in `0x21..=0x7e`.

The lifecycle-continuity schema is a separate host-only artifact. The verifier
checks the synthetic registration-candidate metadata snapshot and first
activation, then recomputes same-root recovery, opposite-delta refresh, the
changed role-local aggregates, the preserved downstream identity trace, strict
epoch promotion, and all three activation origins with zero evaluation counts.
The registration snapshot has all-zero represented-work counters and makes no
registration-evaluator claim. It makes no claim about production custody, Yao
execution, output packages, or distributed cutover.

The ceremony-context schema freezes five strict cases. The verifier rebuilds
the ordered LP32 public request, branch authorization, and final transcript
encodings directly from source fields, hashes each layer, and checks both DAG
edges. It enforces exact protocol version one, required identity and deployment
metadata, request-derived circuit/recipient/output mappings, strictly advancing
refresh epochs, canonical export public keys, and nonzero opaque suite slots.
The activation-control case must reference the coherent registration origin;
activation and export origin kinds, current-context reuse, and independently
spliced origin digests are rejected. Provenance ceremony bindings include and
must match the outer evaluation request kind. Provenance CLI verification also
requires this ceremony corpus and compares every registration, recovery,
refresh, and export digest tuple with the request, authorization, and transcript
digests independently rebuilt from its matching ceremony case.

The output-sharing schema is another strict host-only artifact. The verifier
freezes its six activation/export cases and independently recomputes the joined
seed, SHA-512 digest, RFC 8032 clamp and scalar, joined blinding scalar, and both
activation-family outputs from the copied source inputs. It then checks the
role-separated scalar shares modulo the Ed25519 scalar order and export seed
shares modulo `2^256`. The deterministic coins provide arithmetic evidence
only; they make no unpredictability, privacy, authentication, or production
randomness claim.

The semantic-lifecycle verifier reconstructs the public activation and export
descriptors, fixed package sets, receipts, persistence projections, three
metadata-consumed activation origins, and uniform rejection self-loops. The
output-party-view verifier then projects that verified public state into seven
closed role extensions. It checks each activation scalar share against its
descriptor point, reconstructs both recipient scalars and the registered-key
relation, reconstructs export seed shares through `d -> A_pub`, and enforces
empty infrastructure views and export-only seed custody. Its synthetic
role-private evidence exists only inside this host corpus; it is not runtime
public leakage, a transport format, or a real/ideal security proof.

The activation-delivery verifier cross-links all three activation origins to
the semantic-lifecycle and output-party-view companions. It independently
checks the not-issued, unconsumed, and consumed authorization timeline; exact
package, receipt, transcript, and public-output identity through uncertainty;
atomic disjoint Client and SigningWorker capabilities; the released Client
scalar against the retained A/B Client-share points; purpose-separated
evidence; zero-work redelivery; and recursive exclusion of worker shares,
roots, ciphertexts, openers, and frames. This remains synthetic host transition
evidence. It provides no production transport, durability, privacy, or
selected-profile security claim.

The activation-recipient party-view verifier keeps the frozen pre-release
output views intact, then checks two separate post-release stages across all
seven roles. It verifies exact release custody, Client-capability retention,
opaque pre-activation worker authority, the synthetic activated worker scalar
against the companion A/B shares and `X_server`, the registered-key relation,
the complete LP32 SigningWorker activation receipt, receipt-key digest, nonzero
storage evidence, and strict Ed25519 signature. Its canonical-corpus trust roots
pin the expected synthetic receipt epoch and verifying key outside the corpus;
coherent key substitution, digest replacement, and re-signing are rejected. The
only allowed `x_server_base_hex` path is the activated SigningWorker extension. Frames,
durable records, openers, ciphertexts, and peer recipient outputs are rejected.
This remains host-only structural evidence and establishes no deployed delivery,
durability, noninterference, or selected-profile security property.

The recovery credential-transition verifier cross-links that verified recovery
activation to the recovery ceremony, provenance, semantic lifecycle, and
delivery companions. It recomputes the complete old/next registered-state
digests, old-version tombstone, exact 20-field promotion receipt, receipt
digest, and strict signature under a verifier-pinned store authority. Coherent
attacker-key body replacement, digest replacement, and re-signing are rejected.
The opaque transaction digest remains host evidence; database atomicity,
rollback floors, replay admission, and crash recovery are outside this claim.

The evaluation-input party-view verifier derives the role-separated accepted-
evaluation inputs from the frozen stable context and lifecycle relations. It
enforces four activation-family inputs per Deriver for registration, recovery,
and refresh; y-only export; zero-input activation; empty infrastructure views;
exact static A/B copies; and branch-specific ideal-function coins outside every
party view. It cross-links all four companion corpora and recomputes the output
shares and registered export key. The inputs and coins are synthetic verifier
evidence. They define no production serialization, entropy source, delivery
claim, or protocol-security theorem.

The uniform-abort verifier checks one exact four-field public envelope for all
five request kinds. It cross-links each public transcript digest to the named
ceremony case and rejects request-context, authorization, blame, peer-frame,
private-payload, alternate-code, and nonterminal fields. This is envelope-shape
evidence only; it proves no failure timing, selective-failure resistance,
ticket destruction, or selected-profile correctness with abort.

The evaluator-abort state/party-view verifier checks registration's
unregistered self-loop, recovery's credential-suspended self-loop, registered
self-loops for refresh/export,
ceremony-bound burned attempt identities, unique nonzero one-use execution
identifiers, and seven role views equal to the exact public abort. It makes no
durable-storage, frame, delivery, timing, ticket-destruction, or profile claim.

The artifact mutation suite also obtains the canonical `EYAOBM01` candidate
bytes from the generator CLI and independently decodes every compiler, ordering,
schema, bundle-index, component, digest, circuit/schedule metric, and passive-
table field in stdlib Python. It recomputes the domain-separated manifest digest
and rejects prefix, component, or wrapped-index mutation. This cross-language
check does not make the Rust exact-regeneration parser an independent parser and
does not grant the candidate production authority.

All inputs are committed or generated public test vectors. The arithmetic is
variable-time Python intended solely for host-side verification. Production
protocol code and secret material must never depend on this directory.
The artifact verifier is early FV2 evidence only. It does not close Phase 2B,
approve the candidate as a final protocol manifest, or authorize production
artifact loading.

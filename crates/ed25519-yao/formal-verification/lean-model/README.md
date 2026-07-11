# Ed25519 Yao Lean Model

The current FV1 model contains exactly 122 theorems.

The FV1 Lean model contains three manifest rehearsal theorems for distinct
activation/export family bytes, seven digest slots, and thirteen metrics. Nine
additional structural party-view theorems model profile-neutral output custody:
role separation, public-only infrastructure views, export-client-only seed
visibility, a public-only SigningWorker across all five frozen stages, metadata-
only activation, and static single-Deriver observation.

Twenty-two evaluation-input policy theorems model the same five frozen lifecycle
stages with family-specific value classes. They establish the exact four
role-local activation inputs for registration, recovery, and refresh; the exact
two role-local seed-domain inputs for export; the absence of activation inputs
and coins; private-input-free client and infrastructure views; peer-input
exclusion; family-correct use of functionality-owned output-sharing coins; the
exact stage/request/plan/count and pre-state-class tables; the seven-role
universe; and exact static A/B observation.

Across the five frozen host output stages, the SigningWorker has common public
metadata only. Actual package opening and an activated/delivered SigningWorker
state remain outside this model and require a later normative stage.

These party-view theorems are policy-shape evidence. They do not establish
noninterference, real/ideal security, protocol privacy, delivery, or production
custody.

The evaluation-input model is also policy-shape evidence. Its pre-state theorem
classifies stages and does not authenticate a store or companion artifact. It
has no executable runtime bridge and makes no noninterference, protocol-
security, coin-sampling, or production-custody claim.

Four uniform-abort theorems freeze the exact four public fields, exclude
request-context, authorization, Deriver-blame, and private-payload fields, and
assign the same redacted code and terminal state to all five request kinds.
They do not prove when an implementation aborts, timing equivalence, selective-
failure resistance, or correctness with abort.

Seven evaluator-abort theorems freeze the four evaluator request kinds,
activation exclusion, the unregistered/credential-suspended/registered state table, self-loop
transition, exact seven-role set, and common-only uniform-abort field view.
They do not prove durable state, ticket destruction, delivery, or timing.

Seven export-delivery theorems freeze authorization as unconsumed at output
commitment and uncertainty, consumed at release, exact identity preservation
through uncertainty and redelivery, Client-only seed visibility, and zero
private-evaluation work. They do not prove ciphertext opening, authenticated
transport, durable replay, acknowledgement, or selected-profile security.

Ten activation-delivery theorems freeze the not-issued, unconsumed, and
consumed authorization timeline; exact custody through uncertainty and
redelivery; atomic distinct Client and SigningWorker capabilities; released
Client scalar reconstruction; typed worker-authority identity; and zero private
work for uncertainty, release, and redelivery. They are host-only structural
evidence and do not prove ciphertext opening, authenticated transport, durable
replay, complete runtime views, or selected-profile security.

Twelve activation-recipient party-view theorems freeze the two post-release
stages and seven roles; empty pre-release extensions; exact Client scalar and
opaque SigningWorker authority custody at release; sealed SigningWorker custody
after activation; identity continuity; redelivery stability; and exclusion of
retained Deriver shares from every recipient extension. They are host-only
policy-shape evidence and do not prove frames, durable delivery, erasure,
noninterference, or selected-profile security.

Twelve recovery-credential transition theorems freeze active-to-suspended
cutover; evaluator-abort self-loop behavior; exact suspension retention through
output commitment, metadata consumption, recipient release, and worker
activation; verified-authority-only promotion; distinct replacement activation;
old-credential tombstoning; public-key, stable-scope, and A/B binding continuity;
strict state-version and activation-epoch advancement; and exclusion of dual
active credentials. They are construction-independent policy-shape evidence and
do not prove durable transactions, recovery proof verification, authenticated
transport, crash recovery, or selected-profile security.

Twelve export evaluator-authorization theorems require separate Deriver A and B
verified capabilities, distinct role authorities, and equality of their request,
authorization, transcript, provenance pair, authenticated store state/identity,
and one-use execution bindings. They also freeze exactly one accepted export
evaluation, preserve the acceptance-pair digest through output commitment and
release, and move authorization from unconsumed to consumed. These are host-only
capability and equality theorems. Signature unforgeability, trusted A/B key
distribution, admission-clock integrity, authorization-record policy validity,
durable replay, transport, constant-time execution, and P0-P3 protocol security
remain assumptions or later obligations.

Twelve registration evaluator-admission theorems freeze the public
unregistered pre-state classification, durable identity scope,
request/authorization/transcript/intent/provenance binding, both opaque
input-selection evidence identities, checked-at expiry, activation epoch and
execution identity, exactly one evaluation, candidate/receipt identity,
candidate retention through metadata and worker activation, and terminal
selection retention on abort. They do not prove authenticated absence, durable
uniqueness, input-opening consistency, selected-profile security, or production
constant-time behavior.

Twelve recovery evaluator-admission theorems freeze the active-to-suspended
boundary; durable identity, request, authorization, transcript, ordered
provenance, authenticated store authority, complete registered identity,
credential transition, both continuity-evidence identities, checked-at expiry,
strict activation-epoch advancement, and execution identity; exactly one
evaluation; terminal retention through output commitment and worker activation;
and exact suspension, terminal, and burned-execution retention on abort. They do
not prove same-root evidence validity, selected-mechanism acceptance,
authenticated store verification, durable replay, selected-profile security, or
production constant-time behavior.

```sh
cargo yao-fv lean-check
```

The task builds the explicit `Ed25519YaoModel` target, checks an exact nonzero
theorem count, and requires its `.olean` output. This handwritten model has no
generated production or Verus bridge, so it is not evidence for the checked
manifest obligations. No complete or executable runtime party-view,
corruption-game, simulator, privacy, or protocol-security model is present.

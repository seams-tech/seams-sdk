# Ed25519 HSS Refactor 3

Date updated: April 5, 2026

## Summary

This document records the next required protocol refactor for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

The explicit invariant is:

- in all non-export production flows, the client must never be able to
  reconstruct per-account `y_relayer`
- in all non-export production flows, the client must never be able to
  reconstruct per-account `tau_relayer`

This is stronger than passive wire confidentiality. It is a malicious-client
boundary requirement.

Explicit exception:

- `ExplicitKeyExport` is allowed to deliver the canonical seed to the authorized
  client
- that operation therefore intentionally falls outside the non-export secrecy
  invariant for `y_relayer` and `tau_relayer`
- every other production flow must still satisfy the stronger non-reconstruction
  boundary

The old sealed `ServerInputsPacket` flow did not satisfy this invariant. The
evaluator could open a sealed packet containing both relayer transport halves,
which was enough for a malicious evaluator implementation to reconstruct the
per-account relayer-side hidden inputs.

So this is not a small hardening patch. It is a protocol redesign.

Scope of this invariant:

- it applies to all non-export production client boundaries
- it applies to networked browser/relay mode
- it applies to same-process and local APIs that are part of production
  execution paths
- it applies to browser wasm exports and worker surfaces

Concretely, this means the invariant must hold for:

- packet/wire seams
- `PreparedSession::evaluate*` style production APIs before they were removed
- any evaluator-visible `Trusted*` helper object
- browser/client wasm exports
- runtime/session objects that can exist in production client memory

Current implementation status:

- the legacy sealed `ServerInputsPacket` seam is gone from the production
  client boundary
- `PreparedSession::evaluate*` no longer exists on the production public
  surface
- the production staged flow now advances through real stage-local server-owned
  continuations from add-stage onward:
  - add-stage materializes only the add-stage transition plus the first stored
    `message_schedule` continuation
  - each `message_schedule(n)` response advances only the immediately prior
    schedule continuation
  - each `round_core(n)` response advances only the immediately prior
    round-core continuation
  - `output_projection` materializes final output only when that stage executes
- `ServerAssistInit` is now just the authenticated init/handle handoff; the
  hidden-eval execution state begins at the first online add-stage request
- the stronger continuation-architecture follow-up is tracked in
  [refactor-hss-4.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/refactor-hss-4.md)
- the remaining work after this refactor is cleanup, constant-time review, and
  broader malicious-security hardening beyond this boundary fix

## Why This Refactor Is Required

The current design protects against:

- passive wire interception
- transcript swapping and mismatched packet binding
- accidental broad in-memory propagation of opened relayer transport

The current design does **not** protect against:

- a malicious client endpoint that opens the server-input packet and reconstructs
  the relayer-side inputs

That means the deployed packet flow is still too weak for the intended product
security statement.

If the client can reconstruct:

- `y_relayer`
- `tau_relayer`

then the client can combine those with:

- its own `y_client`
- its own `tau_client`

and derive the full per-account hidden key lifecycle. That is exactly what must
be prevented.

## Relationship To Existing Docs

This plan is grounded in:

- [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- [succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
- [docs/homomorphic-secret-sharing.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/homomorphic-secret-sharing.md)
- [docs/semihonest-to-malicious-secure.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/semihonest-to-malicious-secure.md)

## Is `semihonest-to-malicious-secure.md` Relevant?

Yes, but it is not sufficient by itself.

It is relevant because it already frames:

- malicious-client threat models
- repeated probing by an authenticated client
- the need for stronger transcript, OT, and Beaver protections

It is not sufficient because the issue here is even more basic:

- the current honest runtime gives the client enough material to reconstruct the
  per-account relayer inputs after opening the sealed packet

So this refactor should be treated as a prerequisite boundary correction for any
credible malicious-client story.

In other words:

- `semihonest-to-malicious-secure.md` is the broader malicious-security roadmap
- this refactor is the concrete protocol redesign needed to stop direct relayer
  input reconstruction by the client

## Current Unsafe Boundaries

Today:

1. the server derives joint relayer-side hidden input bundles
2. one unsafe path seals both relayer transport halves into `ServerInputsPacket`
3. the evaluator opens the packet
4. the evaluator receives:
   - `y_relayer_left`
   - `y_relayer_right`
   - `tau_relayer_left`
   - `tau_relayer_right`
5. the evaluator consumes those opened bundles in the hidden-eval path

There is also a second unsafe boundary in the same-process/local flow:

1. the server-side prepared/evaluate path builds `TrustedServerEval`
2. `TrustedServerEval` contains `trusted_server_inputs`
3. `trusted_server_inputs` is built from both relayer halves
4. evaluator-side execution consumes
   `trusted_server_eval.trusted_server_inputs.y_relayer_bits` and
   `trusted_server_eval.trusted_server_inputs.tau_relayer_bits`

So deleting only `ServerInputsPacket` is not sufficient.

This is acceptable for:

- passive wire secrecy
- honest-runtime evaluation

This is not acceptable for:

- malicious evaluator secrecy

## Target Boundary

After this refactor:

- the evaluator may compute on server-owned hidden inputs
- the evaluator must never receive both relayer share halves in reconstructable
  form
- the evaluator must not be able to decode per-account `y_relayer`
- the evaluator must not be able to decode per-account `tau_relayer`
- the server must keep the missing relayer-side decode material on the server
  side for the entire online flow

That means the client must move from:

- “evaluate on fully delivered server transport bundles”

to:

- “evaluate with server assistance, or evaluate with garbled/server-authored
  artifacts that do not expose a decodeable relayer secret”

## Non-Goals

This plan is not trying to:

- preserve the current `ServerInputsPacket` seam for compatibility
- keep duplicate legacy packet types around
- defer cleanup behind feature flags

Breaking changes are expected.

## High-Level Redesign Options

There are only a few credible ways to satisfy the invariant.

### Option A. Interactive Server-Assisted Nonlinear Evaluation

The evaluator never receives both server halves. The server keeps one relayer
share side and participates in the online phase whenever nonlinear operations
need server-owned material.

Pros:

- directly enforces the boundary
- clearest security story

Cons:

- more network round trips
- larger protocol refactor

### Option B. Real Garbled/Encoded Server-Input Delivery

The server sends an encoded form that lets the evaluator continue the hidden
computation without revealing reconstructable relayer values.

Pros:

- may preserve more of the current client execution model

Cons:

- harder to reason about
- easy to accidentally reintroduce a decode path

### Option C. Hybrid: Server-Assisted Input Projection, Client-Side Core

The server keeps the relayer-side secret through input projection and only hands
the evaluator derived non-decodeable stage state.

Pros:

- smaller round-trip increase than full interactive evaluation

Cons:

- must be proved carefully
- likely still requires redesign of stage entry and output projection

## Recommended Direction

Recommended default: Option A.

Reason:

- it is the most direct way to satisfy the invariant
- it is easiest to audit
- it avoids subtle “encoded but still decodeable” mistakes

The evaluator should not receive both halves of any relayer-owned hidden input
at any production boundary.

## Required Non-Negotiable Requirements

These are mandatory for this refactor:

1. `TrustedServerEval` and any evaluator-visible `DdhHiddenEvalServerInputs`
   style object must be deleted from production client/runtime surfaces, or
   moved to server-only ownership where the evaluator cannot observe both
   relayer halves.
2. The exact interactive/server-assisted state machine must be written down
   before implementation starts.
3. Reconstruction-attempt tests must exist for every production boundary, not
   just byte-presence or field-absence tests.
4. Output-boundary review is mandatory, not optional.

## Recommended Interactive State Machine

If Option A is chosen, the protocol should be defined at this level of
precision before coding begins.

### Exact Messages Per Round

The initial safe protocol should define these exact message families.

Canonical naming rule:

- use only the message names in this section throughout the plan
- do not introduce alternate names like `*ContinuationPacket` or generic
  “successor request type” wording
- if the message set changes, update this section first and propagate the exact
  names everywhere else

Client to server:

- `ClientOtRequestPacket`
  - carries:
    - `context_binding`
    - `transcript_id`
    - `client_ot_request`
    - `client_request_commitments`
- `ClientStageRequestPacket`
  - carries:
    - `context_binding`
    - opaque `server_eval_handle`
    - `stage_id`
    - `prior_transcript_digest`
    - typed `client_stage_payload`
    - `client_stage_commitments`

Server to client:

- `ServerAssistInitPacket`
  - carries:
    - `context_binding`
    - opaque `server_eval_handle`
    - `transcript_id`
    - `server_input_commitment`
    - `y_client_response`
    - `tau_client_response`
    - `y_client_remote_release`
    - `tau_client_remote_release`
  - must **not** carry:
    - `y_relayer_left`
    - `y_relayer_right`
    - `tau_relayer_left`
    - `tau_relayer_right`
    - `DdhHiddenEvalServerInputs`
    - `TrustedServerEval`
- `ServerStageResponsePacket`
  - carries:
    - `context_binding`
    - opaque `server_eval_handle`
    - `stage_id`
    - `next_transcript_digest`
    - typed `server_stage_payload`
    - `server_stage_commitments`
  - must **not** carry any reconstructable relayer-root material
- `ServerFinalizePacket`
  - carries:
    - `context_binding`
    - opaque `server_eval_handle`
    - final transcript digest
    - operation-authorized output packets only

### Exact Round Structure

Round 0. Prepare

- server prepares context-bound artifact and server-private relayer-side state
- client receives only evaluator-safe prepared material
- client does not receive both relayer halves

Round 1. Client input delivery

- client sends:
  - client OT request material
  - context-bound transcript identifiers
  - any client-owned commitments needed for the next step
- client retains:
  - client OT local state
  - client-owned `y_client` / `tau_client`

Round 2. Server-assisted server-input projection

- server consumes:
  - client OT request material
  - server-private relayer-side state
- server returns:
  - only the minimum evaluator-safe continuation material required for the next
    hidden-eval step
- server retains:
  - at least one non-decodeable relayer-side factor for the entire online flow
  - any state required to prevent client reconstruction of `y_relayer` and
    `tau_relayer`

Round 3+. Nonlinear progression

- each nonlinear stage that would otherwise require both relayer halves must be
  completed with explicit server participation or server-authored
  non-decodeable continuation state
- the client must never accumulate enough state across rounds to reconstruct the
  relayer roots

Final round. Output release

- client receives only the client-authorized outputs for the operation
- any server-owned output must be reviewed under the same non-reconstruction
  rule

### Exact Initial Round Batching

The initial secure implementation should use the following round granularity.

- 1 `ClientOtRequestPacket`
- 1 `ServerAssistInitPacket`
- 1 add-stage round:
  - `ClientStageRequestPacket(AddStageRequestPayload)`
  - `ServerStageResponsePacket(AddStageResponsePayload)`
- 64 message-schedule rounds:
  - one request/response pair per derived schedule word
- 80 round-core rounds:
  - one request/response pair per SHA-512 round
- 1 output-projection round:
  - `ClientStageRequestPacket(OutputProjectionRequestPayload)`
  - `ServerStageResponsePacket(OutputProjectionResponsePayload)`
- 1 `ServerFinalizePacket`

This is intentionally conservative and likely slower than the final optimized
design.

Rule:

- no stage batching beyond this may be introduced until the batched payload is
  shown to remain non-reconstructable under malicious-client accumulation tests

### Exact Server-Private State Persisted Across Rounds

Server-private for the entire flow:

- `context_binding`
- `transcript_id`
- current `stage_id`
- current `transcript_digest`
- expiration / one-time-use / replay metadata
- per-account `y_relayer`
- per-account `tau_relayer`
- any relayer hidden bundles derived from those values
- OT sender state and remote-release state
- any server-local continuation state for:
  - add-stage entry
  - message-schedule accumulation
  - round-core progression
  - output projection
- any server-side half or continuation artifact that, when combined with
  client-visible state, would reveal `y_relayer` or `tau_relayer`

### Exact Client-Visible Transient State Allowed

Client-visible transient state may include:

- `ClientOtOffer`
- `ClientOtState`
- `ClientOtRequestPacket`
- `ServerAssistInitPacket`
- opaque `server_eval_handle`
- `transcript_id`
- `stage_id`
- `prior_transcript_digest`
- `next_transcript_digest`
- transcript identifiers
- client OT local state
- client-owned commitments
- evaluator-safe continuation material required for the next step
- final client-authorized output packets

Client-visible transient state must be:

- single-stage scoped where possible
- single-use where possible
- context-bound
- transcript-bound

Client-visible state must never include:

- both relayer transport halves for any server-owned input
- any equivalent encoded form that allows offline reconstruction
- any `Trusted*` helper object that embeds reconstructable relayer input state
- any output packet that reconstructs server-owned secrets not explicitly
  allowed for that operation

### Exact Client State Stored Between Rounds

The client may store only:

- `ClientOtState`
- client-owned reconstructed bundles for `y_client_bits` and `tau_client_bits`
- opaque `server_eval_handle`
- latest accepted `stage_id`
- latest accepted `transcript_digest`
- latest single-use `ServerStageResponsePacket`
- latest unsent `ClientStageRequestPacket` until acknowledged

The client must not store between rounds:

- relayer transport bundles
- `DdhHiddenEvalServerInputs`
- `TrustedServerEval`
- both halves of any server-owned output
- any decoded relayer root input

### Exact Nonlinear Steps Requiring Server Participation

The conservative initial implementation should require server participation for
every production stage that consumes state descended from server-owned relayer
inputs.

That means server participation is required for:

- add-stage entry where:
  - `y_client + y_relayer` feeds the seed path
  - `tau_client + tau_relayer` feeds the rerandomization path
- message-schedule accumulation and carry propagation
- round-core progression, including:
  - `Ch`
  - `Maj`
  - carry/add networks
  - `temp1`
  - `temp2`
  - `new_a_bits`
  - `new_e_bits`
- output projection for any server-owned output contribution, including
  `x_relayer_base`

Initial rule:

- if a stage consumes state descended from relayer-owned inputs, the server
  participates
- only after proving a continuation payload is non-reconstructable may a stage
  be collapsed back to the client side

### Typed Per-Stage Payload Schemas

The initial implementation should not use one generic continuation blob.

Instead:

- `ClientStageRequestPacket.client_stage_payload` must be a tagged enum
- `ServerStageResponsePacket.server_stage_payload` must be a tagged enum

Initial stage families:

- `AddStageRequestPayload`
- `AddStageResponsePayload`
- `MessageScheduleRequestPayload`
- `MessageScheduleResponsePayload`
- `RoundCoreRequestPayload`
- `RoundCoreResponsePayload`
- `OutputProjectionRequestPayload`
- `OutputProjectionResponsePayload`

Each payload schema must define:

- exact fields
- exact transcript binding inputs
- exact commitment checks
- whether the payload is retry-idempotent
- whether the payload may be stored client-side after use

Initial exact field sets to critique:

- `AddStageRequestPayload`
  - `client_input_commitment`
  - `client_stage_openings_digest`
  - `client_stage_nonce`
  - semantics:
    - `client_input_commitment` binds the client-owned `y_client_bits` and
      `tau_client_bits`
    - `client_stage_openings_digest` is
      `H("add_stage_request", context_binding, handle, stage_id, client_stage_nonce, client-owned stage inputs)`
    - `client_stage_nonce` is client-generated and single-use for this stage
- `AddStageResponsePayload`
  - `server_stage_token`
  - `server_input_commitment`
  - `server_stage_digest`
  - semantics:
    - `server_stage_token` is a server-authenticated capability scoped to
      `(handle, stage_id, transcript_digest)`
    - `server_input_commitment` binds the relayer-side inputs without revealing
      them
    - `server_stage_digest` is
      `H("add_stage_response", context_binding, handle, stage_id, prior_transcript_digest, server_input_commitment, server_stage_token)`

- `MessageScheduleRequestPayload`
  - `schedule_step`
  - `client_schedule_digest`
  - `prior_server_stage_digest`
  - semantics:
    - `schedule_step` is exact and monotonic
    - `client_schedule_digest` is
      `H("message_schedule_request", context_binding, handle, stage_id, schedule_step, client-local schedule carry/openings)`
- `MessageScheduleResponsePayload`
  - `schedule_step`
  - `server_schedule_digest`
  - `next_stage_token`
  - semantics:
    - `server_schedule_digest` is
      `H("message_schedule_response", context_binding, handle, stage_id, schedule_step, prior_server_stage_digest, next_stage_token)`

- `RoundCoreRequestPayload`
  - `round_index`
  - `client_round_digest`
  - `prior_server_stage_digest`
  - semantics:
    - `round_index` is exact and monotonic
    - `client_round_digest` is
      `H("round_core_request", context_binding, handle, stage_id, round_index, client-local round openings/state digest)`
- `RoundCoreResponsePayload`
  - `round_index`
  - `server_round_digest`
  - `next_stage_token`
  - semantics:
    - `server_round_digest` is
      `H("round_core_response", context_binding, handle, stage_id, round_index, prior_server_stage_digest, next_stage_token)`

- `OutputProjectionRequestPayload`
  - `final_client_digest`
  - `prior_server_stage_digest`
  - semantics:
    - `final_client_digest` is
      `H("output_projection_request", context_binding, handle, stage_id, client-final projection digest)`
- `OutputProjectionResponsePayload`
  - `final_server_digest`
  - `output_release_token`
  - `allowed_output_kind`
  - semantics:
    - `final_server_digest` is
      `H("output_projection_response", context_binding, handle, stage_id, prior_server_stage_digest, output_release_token, allowed_output_kind)`
    - `output_release_token` authorizes exactly one finalization of the allowed
      output kind

These payloads are intentionally digest/token-heavy and data-light. The first
implementation should bias toward:

- commitments
- transcript digests
- stage tokens

and away from shipping raw stage state.

Payloads must never contain:

- both relayer share halves
- relayer transport bundles in paired reconstructable form
- any object equivalent to `DdhHiddenEvalServerInputs`
- any server-authored state that becomes reconstructable when accumulated across
  rounds

Initial conservative payload rule:

- `ClientStageRequestPacket` may carry only client-owned openings,
  commitments, and transcript-bound stage inputs
- `ServerStageResponsePacket` may carry only stage-local evaluator-safe
  continuation material that is individually non-reconstructable and
  non-accumulating

### Exact Output Policy

The initial secure design should enforce this explicit output policy.

- registration:
  - allowed output kind: `client_output_only`
  - client may receive/open:
    - client output for `x_client_base`
  - client may not receive/open:
    - relayer output
    - seed output
- tx signing:
  - allowed output kind: `client_output_only`
  - client may receive/open:
    - client output for `x_client_base`
  - client may not receive/open:
    - relayer output
    - seed output
- link device:
  - allowed output kind: `client_output_only`
  - client may receive/open:
    - client output for `x_client_base`
  - client may not receive/open:
    - relayer output
    - seed output
- email recovery:
  - allowed output kind: `client_output_only`
  - client may receive/open:
    - client output for `x_client_base`
  - client may not receive/open:
    - relayer output
    - seed output
- warm-session reconstruction:
  - allowed output kind: `client_output_only`
  - client may receive/open:
    - client output for `x_client_base`
  - client may not receive/open:
    - relayer output
    - seed output
- explicit key export:
  - allowed output kind: `client_output_and_seed_output`
  - client may receive/open:
    - client output for `x_client_base`
    - seed output for canonical export
  - client may not receive/open:
    - relayer output in reconstructable form

Hard rule:

- no non-export operation may release seed output
- no operation may release relayer output to the client in reconstructable form

### Handle, Authorization, And Retry Model

`server_eval_handle` must be treated as both a lookup key and an
authorization-bound protocol capability.

Initial required semantics:

- handle format:
  - unguessable random 128-bit or 256-bit identifier
  - server-generated
  - opaque to the client
- handle lookup:
  - server-side state map from `server_eval_handle -> ServerEvalState`
- authorization:
  - every handle lookup must also verify:
    - authenticated client/session identity
    - `context_binding`
    - operation kind
    - allowed stage transition
- stage monotonicity:
  - each handle has exactly one current `stage_id`
  - only the next expected stage may be entered
- retries:
  - duplicate `ClientStageRequestPacket` with the same
    `(handle, stage_id, request_digest)` must be idempotent
  - duplicate request with different payload under the same
    `(handle, stage_id)` must be rejected
- concurrency:
  - concurrent requests on the same handle must be serialized or rejected
- abort:
  - aborted or expired handles are invalid forever
- completion:
  - finalized handles are consumed and cannot be reused

The plan should assume the stricter version by default:

- handle reuse across stage rollback is forbidden
- stage re-entry is allowed only for exact retry of the same request digest

## Proposed Implementation Sketch

This section is the concrete starting proposal to critique before coding.

### Core Design Choice

Use an opaque server-side evaluation handle and make the server own all
relayer-input state for the full online flow.

The client may retain:

- client OT local state
- client-owned reconstructed bundles
- transcript bindings
- stage-local continuation data that is explicitly designed to be
  non-reconstructable

The client may not retain:

- both relayer transport halves
- any `TrustedServerEval`-style helper carrying server-owned hidden inputs
- any server-authored continuation object that can be deterministically turned
  back into `y_relayer` or `tau_relayer`

### Proposed New Online Flow

Round 1. Client OT request

- client calls a replacement for `prepare_client_ot_request`
- client sends:
  - `ClientOtRequestPacket`

Round 2. Server assist init

- server reconstructs/stores:
  - relayer-side hidden input state
  - OT sender state
  - transcript binding
- server returns:
  - client OT responses
  - client OT remote releases
  - opaque `server_eval_handle`
  - server-input commitment
- server does **not** return both relayer halves

Round 3. Client local step

- client reconstructs only client-owned OT bundles
- client computes the exact next-step client-authored openings/continuation data
  needed by the protocol
- client sends:
  - `server_eval_handle`
  - client-authored continuation payload
  - transcript-bound stage identifier

Round 4+. Server-assisted nonlinear progression

- server looks up `server_eval_handle`
- server advances the protocol using:
  - retained relayer-side state
  - retained server-authored stage state
  - new client-authored continuation payload
- server returns only the next evaluator-safe continuation material
- repeat until output finalization

Final round

- server finalizes the server-owned output path
- client receives only operation-authorized client-visible outputs
- export, if allowed, remains an explicit special case and must be isolated from
  normal signing/registration flows

Plainly stated execution model:

- the initial secure design is effectively server-driven for the entire
  nonlinear core
- the client remains the OT receiver and the owner of client-side secret input
  state
- the server remains the owner of all relayer-descended nonlinear state
- this is not a lightly assisted evaluator design; it is a staged
  client/server protocol where the nonlinear core advances under explicit
  server participation

### Opaque Handle Model

Introduce a server-only handle type, for example:

- `ServerEvalHandle`
- `ServerEvalState`

Stored server-side state behind the handle should include:

- relayer-side hidden input state
- OT sender state / remote release state
- current protocol stage
- transcript binding
- expiration / one-time-use metadata

The handle itself should be:

- opaque to the client
- short-lived
- one-time-use or stage-monotonic
- context-bound

### Replacement Wire Surface

Delete the current unsafe relayer-input packet seam and replace it with a small
set of explicit round messages.

Proposed message families:

- `ServerAssistInitPacket`
- `ClientStageRequestPacket`
- `ServerStageResponsePacket`
- `ServerFinalizePacket`

Explicitly do **not** include:

- `OpenedServerInputs`
- any packet carrying both relayer transport halves
- any packet carrying `DdhHiddenEvalServerInputs`

### Same-Process / Local API Model

The same-process production helpers must follow the same boundary.

Locked decision:

- `PreparedSession::evaluate`
- `PreparedSession::evaluate_hidden_run`
- `PreparedSession::evaluate_with_timing`
- `PreparedSession::evaluate_hidden_run_with_timing`

must be removed from the production public surface.

They may survive only as:

- host-only benchmark helpers
- test-only helpers
- server-only orchestration helpers that do not expose evaluator-visible unsafe
  state

They must not remain callable from:

- browser/client production code
- browser wasm exports
- production evaluator-facing APIs

No same-process production API may return or accept:

- `TrustedServerEval`
- `DdhHiddenEvalServerInputs`
- both relayer halves in reconstructable form

## Concrete Implementation Steps

These are the exact code moves currently proposed.

### Step 1. Introduce Server-Only Evaluation Handles

Target files:

- [src/server/state.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/state.rs)
- [src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
- [src/runtime/evaluation.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/evaluation.rs)

Implement:

- add `ServerEvalHandle` and `ServerEvalState`
- move relayer-side hidden input ownership behind `ServerEvalState`
- delete `TrustedServerEval` from evaluator-visible production paths

### Step 2. Replace Unsafe Wire Messages

Target files:

- [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
- [src/protocol/transcript.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/transcript.rs)
- [src/protocol/invariants.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/invariants.rs)

Implement:

- delete `ServerInputsPacket` from the production protocol
- delete `OpenedServerInputs` from the production protocol
- add the opaque-handle round messages
- bind every new message to:
  - context binding
  - stage id
  - handle id
  - transcript hash / monotonic stage counter

### Step 3. Rewrite Server Round Entry

Target files:

- [src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)

Replace:

- `prepare_trusted_server_eval_timed`
- `seal_server_inputs_packet`
- any method returning evaluator-visible relayer-input objects

With:

- `prepare_server_assist_init_timed`
- `advance_server_assist_stage_timed`
- `finalize_server_assist_stage_timed`

### Step 4. Rewrite Evaluator Entry

Target files:

- [src/client/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs)
- [src/runtime/flow.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/flow.rs)

Delete:

- `open_server_inputs_packet`
- `evaluate_hidden_run_from_trusted_server_eval_timed`
- any evaluator path that consumes `DdhHiddenEvalServerInputs`

Add:

- evaluator helpers that:
  - reconstruct client OT bundles
  - build client-authored continuation payloads
  - apply server-authored continuation payloads
  - never observe reconstructable relayer input state

### Step 5. Rework Hidden-Eval Executor Entry

Target files:

- [src/ddh/hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)
- [src/runtime/flow.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/flow.rs)

Implement:

- new executor entrypoints that consume boundary-safe continuation state
- remove production executor entrypoints that require evaluator-visible
  `DdhHiddenEvalServerInputs`
- keep any joined/server-input reconstruction helper test-only or server-only

### Step 6. Review Output Delivery Under The Same Rule

Target files:

- [src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
- [src/server/outputs.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/outputs.rs)
- [src/client/outputs.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/outputs.rs)
- [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)

Implement:

- explicitly classify which outputs may be reconstructable to the client
- ensure non-export flows do not expose server-owned output material in a way
  that recreates the same leakage problem

### Step 7. Update Browser And Relay Runtime Surfaces Early

Target files:

- [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- [wasm/near_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer)
- browser workers/runtime loaders using the current local evaluator-complete
  flow

Implement:

- remove any wasm export that assumes evaluator-visible relayer input state
- align browser/runtime exports with the new server-assisted rounds

### Step 8. Add Real Reconstruction-Attempt Tests

Target files:

- [tests/boundary/](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/tests/boundary)
- relay/browser integration keep-gates

Implement:

- explicit malicious-client reconstruction attempts against:
  - decoded wire payloads
  - evaluator session/runtime objects
  - same-process production APIs
  - wasm/browser exports
- these tests should attempt to reconstruct `y_relayer` and `tau_relayer`
  directly, not merely assert that certain fields are absent
- add accumulation tests that:
  - collect every client-visible artifact across one full run
  - then attempt reconstruction from the union of those artifacts
- add retry tests that:
  - collect client-visible artifacts across idempotent retry paths
  - then attempt reconstruction from the union of those artifacts
- add repeated-run tests that:
  - collect artifacts across multiple runs for the same account/context
  - then attempt reconstruction from the accumulated set
- add cross-account repeated-run tests to confirm no mixed-context accumulation
  helps reconstruction

## Required Protocol Changes

### 1. Delete `ServerInputsPacket` As A Production Server-Input Delivery Mechanism

The current packet shape is the main problem.

Required result:

- no production packet carries both relayer transport halves to the evaluator

### 2. Delete Or Strictly Server-Confine `TrustedServerEval`

The current same-process/local flow is also unsafe.

Required result:

- no production evaluator/runtime surface may observe `TrustedServerEval` if it
  contains reconstructable relayer-side input state
- no production evaluator/runtime surface may observe
  `DdhHiddenEvalServerInputs`
- local/embedded production APIs must satisfy the same boundary as the wire
  protocol

### 3. Keep Relayer Decode Material Server-Side

The server must retain the missing relayer-side secret material throughout the
online flow.

Required result:

- the client can never reconstruct a relayer-owned hidden input bundle from the
  shipped protocol messages alone

### 4. Redesign The Online Phase Around Server Assistance

The evaluator should submit:

- client OT request material
- context-bound transcript state
- possibly derived local openings required for secure nonlinear progression

The server should answer with:

- only the minimum next-step material needed to continue the protocol
- no packet that lets the evaluator decode per-account relayer roots
- no stage continuation that becomes reconstructable when combined across
  rounds

### 5. Redesign Output Projection And Output Delivery

The current relayer output transport must be reviewed explicitly so the same
mistake is not repeated at the output-share boundary.

Required result:

- the plan must state exactly which server-owned outputs the client may ever
  receive in reconstructable form
- any output that remains reconstructable to the client must be explicitly tied
  to an allowed operation, such as deliberate export
- non-export operations must not accidentally become implicit export lanes

### 6. Make The Boundary Testable

We need explicit negative guarantees:

- evaluator-visible wire payloads cannot reconstruct `y_relayer`
- evaluator-visible wire payloads cannot reconstruct `tau_relayer`
- evaluator-side runtime state cannot reconstruct them either
- evaluator-visible helper objects cannot reconstruct them either
- decoded wire types, runtime/session objects, wasm exports, and worker payloads
  must all be covered

## Code Areas Likely To Change

- [src/server/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs)
- [src/client/api.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs)
- [src/wire/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs)
- [src/protocol/invariants.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/invariants.rs)
- [src/ddh/hidden_eval_executor.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval_executor.rs)
- [src/runtime/flow.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/flow.rs)
- [src/runtime/evaluation.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/runtime/evaluation.rs)
- browser/server wasm seams that currently assume local evaluator completion

## Validation Requirements

This refactor is not complete unless all of these are true:

- no client-visible packet contains both decodeable relayer halves
- no evaluator API can reconstruct `y_relayer` or `tau_relayer`
- no active browser runtime state can reconstruct them
- relay integration tests still pass
- signing/export semantics remain correct
- benchmark regressions are understood and recorded

## Phased Todo List

### Phase 0. Freeze The Unsafe Baseline

- [x] record the exact current unsafe boundary in `security.md`
- [x] record the exact current unsafe packet flow in `succinct-garbling-spec.md`
- [x] inventory current browser/wasm exports and worker/runtime surfaces that
  expose evaluator-visible relayer-side state
  - browser client wasm:
    [wasm/hss_client_signer/src/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer/src/threshold_hss.rs)
    now accepts `serverAssistInitMessageB64u` in
    `threshold_ed25519_hss_evaluate_result(...)`, which routes into the legacy
    evaluator-side joined-input transport seam
  - relay/server wasm:
    [wasm/near_signer/src/threshold/threshold_hss.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/src/threshold/threshold_hss.rs)
    now exports `threshold_ed25519_hss_prepare_server_assist_init(...)`, which
    prepares the staged init boundary but still leaves the client-side
    evaluator on the legacy joined-input execution path
  - browser worker/runtime wrapper:
    [client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts)
    now models `ThresholdEd25519HssServerAssistInitEnvelope` with
    `serverAssistInitMessageB64u`
  - relay runtime wrapper:
    [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
    now calls `threshold_ed25519_hss_prepare_server_assist_init`
  - shared runtime types:
    [server/src/core/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/types.ts)
    and
    [client/src/core/types/signer-worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/types/signer-worker.ts)
    now expose `serverAssistInitMessageB64u` as the staged cross-boundary shape,
    while the evaluator internals still need to stop consuming it through the
    legacy joined-input path
- [x] add one explicit regression test that demonstrates the evaluator can
  reconstruct relayer transport under the old seam
- [x] add one explicit regression test that demonstrates the local
  `TrustedServerEval` path can expose reconstructable relayer input state
- [x] mark that test as the behavior to eliminate, not preserve

### Phase 1. Design The Replacement Online Flow

- [x] choose between:
  - interactive server-assisted evaluation
  - encoded non-decodeable server-input delivery
  - hybrid server-assisted stage entry
- [x] normalize one canonical message vocabulary and remove alternate names
- [x] write the exact round structure
- [x] write a table of:
  - server-private for entire flow
  - client-visible transient state
  - explicitly forbidden client-visible state
- [x] define the browser/wasm production boundary at the same time as the core
  protocol boundary
- [x] define the new wire types
- [x] define handle format, authorization checks, replay semantics, and retry
  idempotency
- [x] define typed payload schemas per stage
- [x] lock the initial round batching:
  - 1 add-stage round
  - 64 message-schedule rounds
  - 80 round-core rounds
  - 1 output-projection round
- [x] define what stays server-private for the full flow
- [x] define which nonlinear stages require server participation
- [x] define what client state is allowed to persist between rounds
- [x] lock the explicit output policy by operation
- [x] define how transcript binding changes
- [x] state explicitly that the initial secure design is server-driven for the
  nonlinear core
- [x] lock the fate of same-process APIs and remove them from the production
  public surface

### Phase 2. Remove The Production `ServerInputsPacket` Seam

- [x] add initial `ServerAssistInitPacket` / `ServerEvalState` scaffolding next
  to the old seam so cutover can happen incrementally without inventing a
  second protocol vocabulary
- [x] add transported `ServerAssistInitPacket` encode/decode and client-side
  validation so the replacement init seam is exercised end-to-end before the
  old packet seam is deleted
- [x] implement the first real stage round:
  - `ClientStageRequestPacket(AddStageRequestPayload)`
  - `ServerStageResponsePacket(AddStageResponsePayload)`
  - handle-backed state transition into `message_schedule(0)`
- [x] implement the first `message_schedule` round:
  - `ClientStageRequestPacket(MessageScheduleRequestPayload)`
  - `ServerStageResponsePacket(MessageScheduleResponsePayload)`
  - handle-backed state transition into `message_schedule(1)`
- [x] make `message_schedule(n)` repeatable so successive validated server
  stage responses drive the next schedule round without falling back to the
  old seam
- [x] expose the new handle-backed init/add-stage/message-schedule wrappers
  through `PreparedSession` so public transport-driven flows can start
  migrating off `ServerPacket`
- [x] implement the first `round_core` round:
  - `ClientStageRequestPacket(RoundCoreRequestPayload)`
  - `ServerStageResponsePacket(RoundCoreResponsePayload)`
  - handle-backed state transition into `round_core(1)` after the final
    `message_schedule(63)` handoff
- [x] make `round_core(n)` repeatable so successive validated server stage
  responses drive later core rounds without falling back to the old seam
- [x] implement the `output_projection` round:
  - `ClientStageRequestPacket(OutputProjectionRequestPayload)`
  - `ServerStageResponsePacket(OutputProjectionResponsePayload)`
  - enforce `allowed_output_kind` from the server-side operation policy
  - finalize handle-backed state at the end of the new path
- [x] expose a single `PreparedSession` helper that drives the staged flow
  through output projection so public wrappers have a direct replacement path
- [x] remove the old joined-input transport convenience wrapper from the public
  `PreparedSession` surface so callers migrate through role APIs or the staged
  replacement path instead of the legacy `ServerPacket` helper
- [x] delete production use of `ServerInputsPacket` for relayer input delivery
- [x] remove evaluator-side `OpenedServerInputs` from the production path
- [x] delete or server-confine `TrustedServerEval`
- [x] delete or server-confine evaluator-visible `DdhHiddenEvalServerInputs`
- [x] update `client/api.rs` and `server/api.rs` to the new online flow
- [x] compute real server-owned hidden-eval checkpoint digests in the
  same-process path so staged handlers can bind to execution-derived state next
- [x] thread execution-derived checkpoint digests through the prepared staged
  same-process flow so add-stage/message-schedule/round-core/output-projection
  responses are no longer transcript-only in that wrapper path
- [x] make prepared add-stage response generation derive execution checkpoints
  from request-carried client bundles plus server-owned relayer roots, instead
  of precomputing a full same-process hidden run up front
- [ ] remove any legacy decode/reconstruction helpers that become obsolete

### Phase 3. Rework Hidden-Eval Entry

- [ ] make hidden-eval entry consume only boundary-safe server material
- [ ] ensure the evaluator never materializes decodeable relayer root input
- [ ] ensure same-process/local production APIs obey the same boundary
- [x] remove the top-level `runtime::evaluate_prime_order_succinct_hss` convenience
  entrypoint from the production public surface
- [x] remove `PreparedSession::evaluate*` from the production public surface
- [x] keep debug/test-only joined helpers out of production code paths
- [ ] re-run constant-time review on new server-assisted steps

### Phase 4. Add Boundary Keep-Gates

- [x] add a multi-round reconstruction-attempt keep-gate for the currently
  implemented new-flow packets, proving accumulated init/add-stage/message-
  schedule artifacts do not drive the legacy relayer decoder
- [x] add a full-run accumulation reconstruction keep-gate for the currently
  implemented staged path through output projection
- [x] add a reconstruction-attempt keep-gate for the public
  `PreparedServerAssistFlow` convenience wrapper
- [x] add direct reconstruction-attempt tests for client-visible packets
- [x] add direct reconstruction-attempt tests for decoded wire types
- [x] add direct reconstruction-attempt tests for evaluator runtime/session
  objects
- [x] add direct reconstruction-attempt tests for wasm/browser exports
- [x] add direct reconstruction-attempt tests for any surviving `Trusted*`
  helper object
- [x] add full-run accumulation reconstruction tests
- [x] add retry/idempotency accumulation reconstruction tests
- [x] add repeated-run same-account accumulation reconstruction tests
- [x] add repeated-run cross-account accumulation reconstruction tests
- [x] prove client-visible packets cannot reconstruct `y_relayer`
- [x] prove client-visible packets cannot reconstruct `tau_relayer`
- [x] prove evaluator runtime state cannot reconstruct them
- [x] add wrong-binding and cross-account negative tests for the new flow

### Phase 5. Update Browser/Relay Runtime Seams

These are part of the security boundary, not just follow-up integration.

- [x] update browser wasm exports to the new protocol
- [x] update relay wasm/runtime usage to the new protocol
- [x] remove any browser export that exposes reconstructable relayer-side state
- [x] ensure browser/client production code cannot call same-process unsafe
  evaluate helpers
- [x] delete stale browser/relay packet code from the old seam
- [x] ensure no duplicate legacy runtime path remains

### Phase 6. Benchmark And Decide

- [x] benchmark latency before/after
- [x] benchmark browser wasm size before/after
- [x] keep the redesign only if the security boundary is actually fixed
- [x] record the cost explicitly in docs

Current recorded Phase 6 results:

- native hidden eval benchmark after the staged seam cut:
  originally recorded as `306.2ms` mean, `305.9ms` median, `309.7ms` p95
  after the focused recovery pass
- prime-order CPU executor benchmark after the staged seam cut:
  originally recorded as `2.40ms` mean, `2.44ms` median, `2.58ms` p95
- browser HSS client artifact after the staged seam cut:
  - wasm: `262,409` bytes
  - JS glue: `14,028` bytes
  - worker JS: `21,744` bytes
- compared with the previous staged baseline just before the final crate seam
  deletion:
  - wasm: `262,439 -> 262,409` bytes
  - JS glue: `14,028 -> 14,028` bytes
  - worker JS: `21,744 -> 21,744` bytes

Fresh post-Refactor-4 rerun:

- native hidden eval:
  `293.47ms` mean, `293.49ms` median, `295.72ms` p95
- hidden eval prepare:
  `207.74ms`
- prime-order CPU executor:
  `2.041ms` mean, `2.041ms` median, `2.044ms` p95
- browser HSS client artifact:
  - wasm: `262,555` bytes
  - JS glue: `14,028` bytes
  - worker JS: `21,744` bytes

Decision:

- keep the redesign
- the security boundary is materially stronger
- one focused executor pass recovered about `7.4ms` from hidden eval by removing
  a per-run SHA-512 constant-pool clone in the round core
- the final seam deletion is size-neutral for the browser HSS artifact
- the remaining follow-up is documentation and broader malicious-security plan
  alignment, not rollback

### Phase 7. Fold Into The Broader Malicious-Security Plan

- [ ] update `docs/semihonest-to-malicious-secure.md` so it references this
  boundary refactor as a prerequisite
- [ ] update `security.md` to remove the current boundary-gap note once fixed
- [ ] update `README.md` and `succinct-garbling-spec.md` to describe the new
  online phase exactly

## Exit Criteria

This refactor is done only when:

- the client cannot reconstruct per-account `y_relayer`
- the client cannot reconstruct per-account `tau_relayer`
- no production boundary delivers both decodeable relayer halves
- no production evaluator/runtime helper exposes reconstructable relayer input
  state
- the specs and docs all say the same thing
- the old unsafe seam has been removed from the codebase

# Trim HSS Registration Artifact Transport

Date created: June 29, 2026

Status: draft plan

## Goal

Reduce the Ed25519 HSS registration finalize payload without weakening the
protocol binding checks.

The immediate target is
`ed25519.evaluationResult.stagedEvaluatorArtifactB64u` in
`/wallets/register/finalize`. A captured registration request measured:

- `154,766` base64url characters for `stagedEvaluatorArtifactB64u`
- `116,074` decoded bincode bytes
- about `38.7KB` of base64url expansion
- about `56.5KB` raw bytes from `server_output_payload`

The first retained change should remove bytes whose authority already belongs
to server-owned finalize state. Deeper protocol and route shape changes can
follow only after this smaller change lands and is benchmarked.

## Scope

This plan owns the transport shape of the client-owned staged HSS evaluator
artifact used during registration finalize.

In scope:

- Rust `StagedEvaluatorArtifact` wire shape
- WASM artifact construction and decode paths
- server finalize/report construction from staged artifacts
- TypeScript route validation for the client-owned artifact envelope
- registration benchmark and tamper-test coverage for the trimmed shape

Out of scope:

- HSS arithmetic/runtime latency optimization
- registration precompute orchestration
- new auth methods
- ECDSA HSS payload shape
- durable Ed25519 restore artifacts

Related plans:

- `docs/refactor-55-hss-optimize-registration.md`
- `docs/refactor-64-optimize-registration-2.md`
- `docs/refactor-74-login-no-hss.md`

## Current Artifact Shape

The current `StagedEvaluatorArtifact` carries:

- backend version
- context binding
- run bindings
- projection metadata
- output projector binding
- client output value kind
- client output commitment
- evaluator witness
- encrypted client output message
- client output binding
- encrypted seed output message
- seed output binding
- server output payload binding
- server output payload

Measured decoded layout from the failing local registration request:

```text
client_output WireMessage      29,563 bytes
seed_output WireMessage        29,516 bytes
server_output_payload          56,466 bytes
everything else                   ~529 bytes
total raw                       116,074 bytes
base64url JSON field            154,766 chars
```

The two output messages are role-gated encrypted packets. The
`server_output_payload` is a serialized pair of server-owned transport bundles:
two `x_server_base` bundles, each with `256` words. Each word includes the share
word plus commitments and provenance metadata.

## Security Read

The client should provide only evaluator-owned output evidence. Server-owned
output material should come from server-owned finalize state.

Current server finalize already recomputes the expected server output payload
from `server_eval_state.finalize_state().output` and rejects an artifact whose
client-sent `server_output_payload` differs. That means the client-sent copy is
not a source of authority. It is a transport copy that the server uses after
confirming exact equality with its own state.

The secure trim is therefore:

- remove `server_output_payload` from the client-owned staged artifact
- remove `server_output_payload_binding` with it
- build the final server output packet directly from server-owned finalize
  state
- keep all existing context, run, digest, projection, and output-message checks

Security invariants that must remain true:

- finalize requires a finalized `ServerEvalState`
- artifact context binding matches the runtime and ceremony
- artifact backend version matches the server session
- client input commitment matches finalize state
- server input commitment matches finalize state
- run binding matches the runtime artifact and both input commitments
- evaluation digest matches runtime output, canonical seed commitment, client
  output value kind, client output commitment, server output commitment, and
  output projector binding
- client output packet is bound to the reported run and evaluation digest
- seed output packet is bound to the reported run and evaluation digest
- client output binding is recomputed over the client output message bytes
- seed output binding is recomputed over the seed output message bytes
- projection mode and client output value kind agree
- operation-specific output delivery still controls whether seed output is
  returned

Do not introduce a compatibility parser for legacy artifacts. This is a
development branch; change the wire shape and update callers/tests together.

## Invariant Review

This trim was checked against the active HSS security docs.

Ed25519 HSS invariant read:

- `crates/ed25519-hss/security.md` and `specs/protocol.md` require the
  non-export path to keep `d`, `a`, `y_server`, and `tau_server` out of the
  client-visible boundary.
- The staged executor docs require server-owned continuation/finalize state and
  final output materialization from stored finalized state.
- The Level A `ClientMaskedProjection` docs require the server path to avoid
  client mask material and client-output bundles while accepting only blinded
  client output for masked projection.
- The formal-verification docs model staged artifacts as carrying projection
  mode, client-output value kind, and client-output commitment metadata, while
  retained server finalize state carries seed commitment metadata and
  server-output transport material.

The proposed trim matches that model: client-owned staged artifacts continue to
carry client-output metadata and sealed client/seed output messages, and the
server derives the server output packet from retained server-owned finalize
state.

ECDSA HSS invariant read:

- `crates/ecdsa-hss/security.md`, `specs/protocol.md`, and `specs/export.md`
  define a role-local additive boundary where the production server never
  reconstructs canonical `x`, the non-export client never receives
  `x_relayer`, and explicit export is the only relayer-share disclosure path.
- The ECDSA integration docs delete the old staged hidden-eval
  prepare/respond/finalize route family in favor of role-local bootstrap and
  explicit export-share routes.

This Ed25519 artifact trim does not touch the active ECDSA HSS route or secret
surface. The shared lesson is to keep server-owned secret/output material on
the server side and pass only public or role-owned evidence across product
boundaries.

One required cleanup follows from the review: the Ed25519 Verus anti-drift
fixture currently constructs `StagedEvaluatorArtifact` with
`server_output_payload_binding` and `server_output_payload`. Phase 1 must update
that fixture and any mirror shape comments so the formal gate reflects the new
artifact boundary.

## Target Shape

Replace the staged artifact with the minimal client-owned state:

```rust
pub struct StagedEvaluatorArtifact {
    pub backend_version: DdhHssBackendVersion,
    pub context_binding: [u8; 32],
    pub bindings: RunBindings,
    pub projection_mode: OutputProjectionMode,
    pub output_projector_binding: OutputProjectorBinding,
    pub client_output_value_kind: ClientOutputValueKind,
    pub client_output_commitment: [u8; 32],
    pub evaluator_witness: EvaluatorWitness,
    pub client_output: WireMessage,
    pub client_output_binding: [u8; 32],
    pub seed_output: WireMessage,
    pub seed_output_binding: [u8; 32],
}
```

Expected size after this phase:

- remove about `56,498` raw bytes
- reduce the sample base64url field from about `154.8KB` to about `79.4KB`
- keep the same finalize route shape at the TypeScript API boundary

## Implementation Plan

### Phase 0: Baseline And Fixtures

- [ ] Add a focused fixture or unit helper that decodes a staged artifact and
      reports top-level field sizes.
- [ ] Preserve the current sample-size expectation as a benchmark baseline, not
      as a hard protocol assertion.
- [ ] Add a tamper fixture proving current finalize rejects mismatched context,
      run binding, evaluation digest, client output binding, and seed output
      binding.

### Phase 1: Trim Server-Owned Payload From Rust Artifact

- [ ] Remove `server_output_payload_binding` from
      `crates/ed25519-hss/src/wire/mod.rs`.
- [ ] Remove `server_output_payload` from the same artifact type.
- [ ] Update client artifact construction in
      `crates/ed25519-hss/src/client/api.rs` so it no longer serializes the
      server output bundle pair into the staged artifact.
- [ ] Update report/finalize construction so server output is sealed from
      `server_eval_state.finalize_state().output`.
- [ ] Keep artifact binding checks in one finalize path. Avoid parallel
      validation helpers that can drift.
- [ ] Delete tests or fixtures that assert the old client-carried server output
      payload.

### Phase 2: Update WASM And TypeScript Boundaries

- [ ] Update `wasm/hss_client_signer/src/threshold_hss.rs` artifact encode
      expectations.
- [ ] Update `wasm/near_signer/src/threshold/threshold_hss.rs` server/client
      export helpers that encode or decode staged artifacts.
- [ ] Keep `stagedEvaluatorArtifactB64u` as the public TypeScript field for this
      phase.
- [ ] Keep route validation strict: `evaluationResult` accepts only
      `contextBindingB64u` and `stagedEvaluatorArtifactB64u`.
- [ ] Update type fixtures so invalid artifact envelope branches remain
      rejected at compile time.

### Phase 3: Verify Security And Size

- [ ] Run Rust protocol tests for staged evaluator artifact finalize.
- [ ] Add or update tamper tests for:
      context binding mismatch, client output binding mismatch, seed output
      binding mismatch, projection mode mismatch, evaluation digest mismatch,
      and stale/non-finalized server eval state.
- [ ] Run `pnpm -C packages/sdk-server-ts run type-check`.
- [ ] Run focused registration route tests that exercise
      `/wallets/register/finalize`.
- [ ] Run one browser registration smoke and record:
      request bytes, `stagedEvaluatorArtifactB64u` chars, decoded artifact bytes,
      finalize duration, and SDK registration duration.

### Phase 4: Consider Binary Transport

Binary transport is a second change after the server-owned payload trim.

- [ ] Measure the remaining artifact size after Phase 1.
- [ ] Decide whether about 25% base64url overhead is worth a route contract
      change.
- [ ] If retained, add an explicit binary finalize body format with a strict
      content type and body-size limit.
- [ ] Keep JSON finalize as deleted or updated in one step. Avoid maintaining two
      long-term finalize encodings.

### Phase 5: Defer Handle-Based Transport

A server-side staged artifact handle would save the most HTTP bytes. It also
adds state lifecycle risk.

Reconsider only if Phase 1 plus binary transport still leaves unacceptable
payload size.

Required handle constraints:

- unguessable id
- single-use consumption
- short TTL
- ceremony binding
- environment/project binding
- authority scope binding
- context binding
- replay protection
- race-safe consume semantics
- explicit cleanup path

## Rejected Shortcuts

- Do not gzip this one field as the main fix. It hides transport cost while
  preserving redundant authority shape.
- Do not keep a legacy artifact parser. Update all artifact producers and
  consumers together.
- Do not remove client output or seed output messages in this refactor. They are
  evaluator-owned encrypted outputs and remain part of the client-owned proof
  surface.
- Do not move control flow decisions into diagnostics or size counters.

## Success Criteria

- `stagedEvaluatorArtifactB64u` is about `75KB` smaller on the captured
  registration shape.
- Finalize still rejects every tampered transcript or binding fixture.
- No TypeScript route accepts legacy artifact-side server output fields.
- Rust and TypeScript type checks pass.
- Focused registration tests pass.
- Browser registration still succeeds against the local D1 router.
- Benchmark notes record before/after request size and finalize latency.

# Formal Verification Implementation Plan

Formal work should begin from the spec documents, especially
[`../../specs/protocol-spec.md`](../../specs/protocol-spec.md) and
[`../../specs/invariants-and-behaviors.md`](../../specs/invariants-and-behaviors.md).
The threat and encoding specs now provide the first concrete model targets:

- [`../../specs/threat-model.md`](../../specs/threat-model.md)
- [`../../specs/encoding-and-transcript.md`](../../specs/encoding-and-transcript.md)
- [`../../specs/minimum-level-c.md`](../../specs/minimum-level-c.md)
- [`../../specs/envelopes-and-delivery.md`](../../specs/envelopes-and-delivery.md)
- [`../../specs/state-machine.md`](../../specs/state-machine.md)
- [`../../specs/secret-classification.md`](../../specs/secret-classification.md)
- [`../../specs/public-share-binding.md`](../../specs/public-share-binding.md)

## Required Invariants

The formal track must model these invariants before the selected candidate is
treated as production-ready:

- context field inclusion and fixed order
- transcript field inclusion and fixed order
- role/output authorization
- forbidden joined-state exclusion from single role views
- recipient separation
- root epoch separation
- replay rejection over changed bound fields
- state-machine transition safety
- vector anti-drift against production Rust helpers
- corruption matrix claims up to Router plus one signer
- package commitment recipient binding
- Minimum Level C evidence field binding
- secret classification excludes forbidden joined-state returns
- public-share-binding evidence implies Minimum Level C evidence

## Required Behaviors

The formal track must model these behaviors:

- client opens only `x_client_base`
- SigningWorker opens only `x_server_base`
- Router cannot observe plaintext A/B derivation shares for one ceremony
- A alone cannot reconstruct forbidden joined state
- B alone cannot reconstruct forbidden joined state
- client view excludes joined server material
- refresh cannot verify new-epoch material under the old epoch
- changed transcript field changes the abstract transcript identity

## Phase 1: Abstract Model

- [x] Model roles: Router, Deriver A, Deriver B, client, SigningWorker
- [ ] Model request kinds: registration, export, refresh
- [ ] Model candidate ids
- [x] Model opened-value kinds
- [x] Model forbidden joined-state kinds
- [ ] Model root epochs
- [ ] Model recipient identities
- [ ] Model ceremony ids
- [x] Prove that allowed opened values match the target invariant

## Phase 2: Encoding And Transcript

- [ ] Mirror `DerivationContext::encode_context_v1`
- [ ] Prove all required fields are included
- [ ] Prove field order is stable
- [ ] Mirror `transcript_binding_digest` at the abstract byte-sequence level
- [ ] Prove transcript includes all role identities
- [ ] Prove changed bound field changes abstract transcript identity
- [ ] Add vector anti-drift tests

## Phase 3: State Machine

- [ ] Model `requested`
- [ ] Model `role_envelopes_created`
- [ ] Model `signer_inputs_accepted`
- [ ] Model `coordination_complete`
- [ ] Model `outputs_bound`
- [ ] Model `delivered`
- [ ] Model `verified`
- [ ] Prove invalid transition rejection
- [ ] Prove no output delivery before signer input acceptance
- [ ] Prove verified output binds the same context accepted by A and B

## Phase 4: Candidate Formula

- [ ] Add the selected candidate formula
- [x] Add Candidate A MPC PRF partial visibility model entry
- [x] Remove Candidate B split-root visibility from the selected production FV surface
- [ ] Prove role-local state separation
- [ ] Prove output scope separation
- [ ] Prove refresh preserves epoch separation
- [ ] Name cryptographic assumptions outside the proof boundary

## Phase 5: Privacy Model

- [x] Model each role's view as explicit public, ciphertext, local-partial,
  recipient-opened, and forbidden-joined events
- [x] Add Candidate A MPC PRF partial visibility privacy entries
- [x] Remove Candidate B split-root privacy entries from the selected
  production FV surface
- [x] Prove a single server-side role cannot observe forbidden joined state in
  the event model
- [x] Prove client view excludes joined `d`, joined `a`, and SigningWorker
  joined material in the event model
- [ ] Prove Router view excludes plaintext A/B derivation shares
- [ ] Connect the Lean model to the Rust role/output types

## Phase 6: Anti-Drift And Release Gate

- [ ] Load committed vectors in proof-crate tests
- [ ] Compare Rust context encoding against model assumptions
- [ ] Compare Rust transcript binding against model assumptions
- [ ] Fail if vector shape changes without proof inventory updates
- [ ] Mark every deferred claim explicitly in the proof inventory

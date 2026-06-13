# Split Derivation Protocol Spec

This document defines the expected behavior before candidate implementation
begins. It is candidate-neutral unless a section explicitly names
`mpc_threshold_prf_v1` or `split_root_derivation_v1`.

Terminology: target protocol prose uses `DeriverA`, `DeriverB`, and
`SigningWorker`. Current implementation labels that still contain `SignerA`,
`SignerB`, or relayer names are transitional and should be renamed in the
slimming refactor.

## Roles

- `Router`: authenticates requests, rate limits traffic, assigns ceremony ids,
  and transports encrypted role envelopes.
- `DeriverA`: holds A-side derivation state and evaluates A-side protocol steps.
- `DeriverB`: holds B-side derivation state and evaluates B-side protocol steps.
- `Client`: receives client-output delivery material and opens only
  `x_client_base`.
- `SigningWorker`: receives SigningWorker-output delivery material and opens
  only `x_relayer_base` for normal signing.

The primitive must be useful with a Router-mediated deployment and with direct
A/B coordination. Routing topology is outside the cryptographic claim. The
state visible to each role is inside the claim.

## Common Inputs

Every ceremony binds:

- `candidate_id`
- `request_kind`
- `correctness_level`
- `network_id`
- `account_id`
- `account_public_key`
- `root_share_epoch`
- `ceremony_id`
- Router identity
- Deriver A identity
- Deriver B identity
- client identity
- SigningWorker identity

These fields must be present in the canonical context or transcript digest.
Missing fields are invalid at the boundary.

## Common Outputs

The primitive may produce:

- client-output delivery material encrypted to the client
- SigningWorker-output delivery material encrypted to the active SigningWorker
- public transcript evidence
- candidate-specific proof or verification material

The primitive must not return raw A/B root shares, joined secret material, or
plaintext output shares to Router.

## Request Kinds

### Registration

Registration creates account-scoped output material for a new account binding.

Required behavior:

- bind account scope and role identities into the transcript
- reject mismatched deriver identities
- reject mismatched root epochs
- derive client-output material only for the client
- derive SigningWorker-output material only for the active SigningWorker
- produce enough public evidence for Minimum Level C transcript verification
- preserve the option to add public-share-binding checks later

### Export

Export derives delivery material for a specific export request.

Required behavior:

- bind export scope into `ceremony_id` or a future explicit export-scope field
- prevent replay across accounts, networks, root epochs, and SigningWorkers
- release client-output material only to the client
- release SigningWorker-output material only to the active SigningWorker
- keep Router as a transport boundary for encrypted role envelopes

### Refresh

Refresh rotates A/B derivation state while preserving the account binding.

Required behavior:

- bind old and new root-share epochs
- bind old and new deriver identities when either role rotates
- reject activation until address verification evidence passes
- avoid reconstructing old or new joined roots
- provide rollback-safe transcript evidence

The current `DerivationContext` has one `root_share_epoch`. A refresh-specific
context extension must be specified before refresh implementation lands.

## Ceremony State Machine

Every request kind uses the same high-level state machine:

1. `requested`: Router has authenticated the request and assigned a ceremony id.
2. `role_envelopes_created`: Router has created role-specific encrypted
   envelopes.
3. `deriver_inputs_accepted`: A and B have accepted their own envelopes and
   validated transcript fields.
4. `coordination_complete`: A/B candidate-specific coordination has completed.
5. `outputs_bound`: output shares or delivery material are bound to transcript
   evidence.
6. `delivered`: encrypted client and SigningWorker delivery material has been
   routed to recipients.
7. `verified`: the verifier has accepted the Minimum Level C checks, or the
   stronger public-share-binding checks when enabled.

Invalid behavior:

- skip directly from `requested` to `delivered`
- accept outputs under a different root epoch
- accept outputs under different deriver identities
- deliver client material to Router, A, B, or SigningWorker
- deliver SigningWorker material to Router, A, B, or client
- retry a ceremony id with changed account scope

## Transcript Binding

The transcript digest must bind:

- context encoding version
- candidate id
- request kind
- correctness level
- account scope
- root epoch
- ceremony id
- Router identity
- Deriver A identity
- Deriver B identity
- client identity
- SigningWorker identity

The digest must be domain separated from any HSS, PRF, signing, storage, or
envelope-encryption digest.

## Minimum Level C Behavior

Minimum Level C must provide:

- transcript-bound outputs
- deriver identity binding
- root epoch binding
- recipient binding
- replay rejection by ceremony id and account scope
- server blindness with respect to joined `d`, `a`, and `x_client_base`

Minimum Level C may allow a malicious client or deriver to cause bad output if
the transcript remains self-consistent. That risk is acceptable for the first
production target only if address verification gates production root rotation.

## Stronger Public-Share-Binding Behavior

The stronger path adds:

- public verifying share binding
- group relation checks against the account public key
- stronger detection for bad deriver output

This path is later hardening work unless benchmarks show the cost is low enough
to include in the first release.

## Error Behavior

Errors must be typed and stable enough for adapters to distinguish:

- malformed input
- unsupported candidate
- unsupported vector version
- mismatched deriver identity
- mismatched root epoch
- replayed ceremony id
- transcript mismatch
- output verification failure
- candidate implementation unavailable

Errors must not include secret material, raw envelopes, raw shares, private
keys, or decrypted delivery material.

## Constant-Time And Secret-Handling Behavior

Candidate implementations must:

- avoid branches on secret scalar bits
- avoid indexing tables by secret material
- avoid secret-dependent loop bounds
- zeroize secret buffers on drop
- keep debug output redacted by type
- use constant-time equality for secret material comparisons

Public context validation can use ordinary branching.

## Persistence Behavior

Persistent state may include:

- root-share epoch labels
- deriver identities
- account scope
- replay cache keys
- public transcript evidence
- encrypted delivery packages

Persistent state must not include:

- joined `d`
- joined `a`
- joined `x_client_base`
- joined `y_relayer`
- joined `tau_relayer`
- plaintext A/B root-share pairs in one record
- decrypted client or SigningWorker delivery material outside the recipient

## Candidate-Specific Spec Gates

Before either candidate can be implemented, it needs:

- exact state held by A and B
- exact coordination messages
- exact combine or delivery location
- exact verification relation
- exact refresh formula
- exact vector cases
- exact leakage table
- exact benchmark targets

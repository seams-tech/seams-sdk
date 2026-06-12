# Ceremony State Machine

This spec defines ownership, persistence, retry, and replay behavior for
Router/A/B derivation ceremonies.

## State Variants

Every ceremony is in exactly one state:

| State | Owner | Meaning |
| --- | --- | --- |
| `requested` | Router | Request authenticated, ceremony id assigned |
| `role_envelopes_created` | Router | Role-specific encrypted signer envelopes created |
| `signer_inputs_accepted` | Signer A and Signer B | Both signers accepted their own input envelope |
| `coordination_complete` | Signer A and Signer B | Candidate-specific coordination finished |
| `outputs_bound` | Signer A and Signer B | Output packages and receipts committed to transcript |
| `delivered` | Router or direct transport | Packages delivered to client and relayer endpoints |
| `verified` | verifier | Minimum Level C or stronger evidence accepted |
| `aborted` | Router or verifier | Ceremony closed without activation |

Core Rust should model this as a tagged enum. Functions should accept the
narrowest state they can operate on.

## Transition Table

| From | To | Created by | Verified by |
| --- | --- | --- | --- |
| none | `requested` | Router | Router auth boundary |
| `requested` | `role_envelopes_created` | Router | Router envelope builder |
| `role_envelopes_created` | `signer_inputs_accepted` | A and B | A and B independently |
| `signer_inputs_accepted` | `coordination_complete` | A and B | candidate-specific verifier |
| `coordination_complete` | `outputs_bound` | A and B | Minimum Level C evidence builder |
| `outputs_bound` | `delivered` | Router or direct transport | delivery receipt checker |
| `delivered` | `verified` | verifier | deterministic verifier |
| any active state | `aborted` | Router or verifier | abort reason validator |

Invalid transitions:

- `requested` to `outputs_bound`
- `requested` to `delivered`
- `role_envelopes_created` to `outputs_bound`
- `outputs_bound` to `role_envelopes_created`
- `verified` to any active state
- `aborted` to any active state

## State Data

### `requested`

Persist:

- ceremony id
- account scope
- request kind
- correctness level
- candidate id
- expected role identities
- signer set id
- quorum policy
- selected relayer identity
- replay-cache key

### `role_envelopes_created`

Persist:

- all `requested` fields
- Signer A envelope header and ciphertext digest
- Signer B envelope header and ciphertext digest
- encrypted-envelope digests indexed by signer index
- transcript digest

### `signer_inputs_accepted`

Persist:

- all `role_envelopes_created` fields
- Signer A accepted-input receipt digest
- Signer B accepted-input receipt digest
- accepted signer-set id
- accepted quorum policy

### `coordination_complete`

Persist:

- all `signer_inputs_accepted` fields
- candidate-specific coordination commitments
- candidate-specific transcript evidence

### `outputs_bound`

Persist:

- all `coordination_complete` fields
- client package commitments
- relayer package commitments
- Signer A output receipt digest
- Signer B output receipt digest

### `delivered`

Persist:

- all `outputs_bound` fields
- delivery receipt digests
- delivery attempt counters

### `verified`

Persist:

- all `delivered` fields
- verified evidence digest
- verifier identity
- verification timestamp or monotonic sequence number

### `aborted`

Persist:

- last active state
- redacted abort reason
- stable error code
- ceremony id
- transcript digest when available

## Replay Cache

Replay cache key V1:

```text
SHA-256(
  lp("router-ab-derivation/replay-cache/v1")
  || lp(ceremony_id)
)
```

Replay cache value V1:

```text
SHA-256(
  lp("router-ab-derivation/replay-value/v1")
  || lp(transcript_digest)
  || lp(candidate_id)
  || lp(request_kind)
  || lp(account_id)
  || lp(root_share_epoch)
)
```

Rules:

- first write for a replay key stores the replay value
- same key and same value is idempotent
- same key and different value is `ReplayMismatch`
- verified and aborted ceremonies remain in replay storage until the product
  retention period expires

## Retry Behavior

Allowed retries:

- Router may recreate the same role envelopes if ciphertext digests match.
- Router may resend the same delivery packages.
- A and B may resend the same authenticated receipts.
- Verifiers may rerun deterministic verification.

Rejected retries:

- same ceremony id with different account scope
- same ceremony id with different role identities
- same ceremony id with different signer set id
- same ceremony id with different quorum policy
- same ceremony id with different selected relayer identity
- same ceremony id with different root epoch
- same idempotency key with different ciphertext digest
- signer receipt for a changed transcript

## Concurrency

Multiple active ceremonies for one account are allowed only when their ceremony
ids differ and their replay values differ. Activation is serialized by account
and root-share epoch.

Refresh activation requires an account-level compare-and-set:

```text
active_epoch == expected_old_epoch
```

Then activation writes:

```text
active_epoch = verified_new_epoch
```

## Abort Behavior

Abort is terminal. Abort records must be redacted. Abort can happen after:

- input validation failure
- replay mismatch
- signer rejection
- coordination failure
- output commitment mismatch
- delivery failure
- verification failure

Aborted ceremonies do not activate root epochs or account bindings.

## Formal Verification Targets

Model:

- valid transition relation
- terminal states
- replay mismatch rejection
- no output delivery before signer input acceptance
- no verified state without output binding
- refresh activation compare-and-set

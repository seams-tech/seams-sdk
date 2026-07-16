# Fixed 2-of-2 Presign Driver v1

Status: implemented isolated checkpoint. The native driver and a deterministic
new/new vertical vector are complete. The canonical byte codec and production
Wasm adapters remain open.

This document freezes the role, round, and validation order implemented by
`driver.rs`. It does not promote the construction for production use. Promotion
still requires the bounded assurance and independent-review gates in
`docs/refactor-89-slimmer-near-ecdsa.md`.

## Fixed roles and inputs

There are exactly two roles:

- Client, which owns the Client additive key share; and
- SigningWorker, which owns the SigningWorker additive key share.

Each role starts with the same `PresignPairContext` and compressed wallet public
key. The API has no participant list, threshold parameter, party identifier, or
runtime role selector. Each round consumes its prior state, making replay or
out-of-order transition impossible through the typed API.

Production sessions derive the signing-scope digest from the fixed protocol ID
and compressed wallet public key under
`seams/router-ab-ecdsa-presign/signing-scope/v1`. They derive the pair digest
from that signing scope and the authenticated server `presignSessionId` under
`seams/router-ab-ecdsa-presign/pair-context/v1`. Both roles therefore obtain the
same context without adding a caller-selected role or topology field. Reusing a
message under a different session ID fails the context checks.

## Round schedule

Both parties compute and send the same numbered round concurrently. A receiver
must authenticate and decode the expected peer role and exact expected round
before invoking the corresponding typed transition.

| Round | Client to SigningWorker | SigningWorker to Client | Required effect before advancing |
| ---: | --- | --- | --- |
| 1 | two polynomial commitments and base-ROT sender hello | two polynomial commitments and base-ROT sender hello | bind both triple polynomials before revealing openings; start opposite fixed base-ROT directions in parallel |
| 2 | two openings, two recipient-private shares, and base-ROT receiver choices | two openings, two recipient-private shares, and base-ROT receiver choices | verify both peer openings and both private shares against the Round 1 commitments; complete the local base-ROT sender |
| 3 | malicious OT-extension correlation | malicious OT-extension correlation | start the fixed extension sender from the peer correlation and local base-ROT receiver output |
| 4 | OT-extension challenge | OT-extension challenge | bind the sender consistency challenge |
| 5 | OT-extension consistency proof | OT-extension consistency proof | verify the peer proof before producing acceptance |
| 6 | OT-extension acceptance | OT-extension acceptance | verify acceptance before exposing either random-OT output; start fixed-direction MTA |
| 7 | MTA ciphertexts | MTA ciphertexts | evaluate the peer ciphertexts with the opposite triple's fixed operands |
| 8 | MTA response | MTA response | verify the response and combine sender/receiver multiplication shares in the role-fixed order |
| 9 | committed triple-finalization contribution | committed triple-finalization contribution | verify the peer contribution and finalize both triples before starting presign equations |
| 10 | `e` share | `e` share | verify and combine the peer `e` share |
| 11 | `alpha`/`beta` shares | `alpha`/`beta` shares | verify the peer shares and release one `PresignOutput` per role |

The logical protocol therefore has eleven bidirectional messages and a local
output step. The implementation test sometimes describes this as twelve stages
by counting output as the terminal stage.

## Mandatory invariants

1. Polynomial commitment messages precede all openings and recipient-private
   shares. Both triple indices are verified independently.
2. The base-ROT and OT-extension directions are fixed by role and triple index.
   Client sends base ROT and extension correlation for triple one, then acts as
   the extension sender for triple zero. SigningWorker sends base ROT and
   extension correlation for triple zero, then acts as the extension sender for
   triple one.
3. Malicious OT-extension proof and acceptance checks complete before random-OT
   outputs enter MTA.
4. MTA directions, operand selection, and multiplication-share combination
   order are fixed in code. Callers cannot select them.
5. Both committed-triple finalization contributions are verified before either
   role constructs its presign input.
6. The exact `PresignPairContext`, wallet public key, and local additive key
   share remain owned by the consuming state chain. No later message may replace
   them.
7. `PresignOutput` is reachable only after all eleven peer-message transitions
   succeed. Any validation failure destroys the consumed state at the API
   boundary.
8. Large OT secret states are boxed and singly owned. This limits stack pressure
   for Wasm/Worker hosts without cloning secret state or weakening consuming
   transitions.
9. The driver creates presign material only. Pool identity binding, durable
   one-use reservation, commitment, material deletion, and tombstoning belong
   to `router-ab-ecdsa-pool` and remain mandatory before online signing.

## Canonical frame encoding

The protocol identifier is
`seams/router-ab-ecdsa-presign/fixed-2of2/v1`. Every message uses a 12-byte
header followed by an exact-width payload:

| Header offset | Width | Meaning |
| ---: | ---: | --- |
| 0 | 4 | ASCII magic `RAEP` |
| 4 | 1 | version `1` |
| 5 | 1 | sender role: Client `1`, SigningWorker `2` |
| 6 | 1 | round number `1..11` |
| 7 | 1 | reserved flags, required to be zero |
| 8 | 4 | unsigned big-endian payload length |

The context is always the first 64 payload bytes: 32 bytes of signing-scope
digest followed by 32 bytes of pair digest. Role-fixed triple indices are not
encoded. The decoder supplies them from the `(sender role, round)` registry,
which prevents callers from selecting an otherwise invalid direction.

| Round | Payload bytes | Total frame bytes | Fixed sender triple index where applicable |
| ---: | ---: | ---: | --- |
| 1 | 161 | 173 | Client base hello `1`; SigningWorker base hello `0` |
| 2 | 4,810 | 4,822 | Client base choices `0`; SigningWorker base choices `1` |
| 3 | 16,448 | 16,460 | Client correlation `1`; SigningWorker correlation `0` |
| 4 | 96 | 108 | Client challenge `0`; SigningWorker challenge `1` |
| 5 | 4,192 | 4,204 | Client proof `1`; SigningWorker proof `0` |
| 6 | 96 | 108 | Client acceptance `0`; SigningWorker acceptance `1` |
| 7 | 49,216 | 49,228 | Client MTA ciphertext `0`; SigningWorker MTA ciphertext `1` |
| 8 | 192 | 204 | Client MTA response `1`; SigningWorker MTA response `0` |
| 9 | 846 | 858 | both contributions ordered triple zero, then triple one |
| 10 | 96 | 108 | role-fixed `e` share |
| 11 | 128 | 140 | role-fixed `alpha`, then `beta` |

One complete presign exchange carries 152,826 bytes across both directions,
excluding the surrounding authenticated transport. The maximum accepted frame
is 49,228 bytes. Decoders reject the wrong magic, version, sender role, round,
flags, payload size, total size, trailing bytes, invalid curve points,
non-canonical scalars, and inconsistent aggregate bindings.

The v1 transcript-domain registry is fixed as follows:

| Purpose | Domain |
| --- | --- |
| polynomial opening | `seams/router-ab-ecdsa-presign/polynomial-opening/v1` |
| discrete-log proofs | `seams/router-ab-ecdsa-presign/proof/v1` |
| base ROT | `seams/router-ab-ecdsa-presign/base-rot/v1` |
| random-OT extension | `seams/router-ab-ecdsa-presign/random-ot-extension/v1` |
| random-OT row PRG | `seams/router-ab-ecdsa-presign/random-ot-row-prg/v1` |
| random-OT output | `seams/router-ab-ecdsa-presign/random-ot-output/v1` |
| random-OT acceptance | `seams/router-ab-ecdsa-presign/random-ot-accept/v1` |
| MTA challenge coefficients | `seams/router-ab-ecdsa-presign/mta-chi/v1` |
| signing-scope derivation | `seams/router-ab-ecdsa-presign/signing-scope/v1` |
| pair-context derivation | `seams/router-ab-ecdsa-presign/pair-context/v1` |

## Requirement-to-code alignment

The classifications in this table are bounded to the isolated Rust checkpoint.

| Requirement | Classification | Evidence |
| --- | --- | --- |
| Fixed Client and SigningWorker roles with no runtime threshold or participant selection | Full | `src/driver.rs`: role-specific message/state types and `start_client_driver` / `start_signing_worker_driver` |
| Consuming, ordered protocol states | Full | `src/driver.rs`: `ClientRound1State` through `ClientRound11State`, SigningWorker equivalents, and their consuming `receive` methods |
| Commit-before-open and private-share verification | Full | `src/driver.rs`: Round 1 and Round 2 transitions |
| Malicious OT-extension proof and acceptance before output use | Full | `src/driver.rs`: Round 3 through Round 6 transitions |
| Fixed-direction MTA and multiplication-share combination | Full | `src/driver.rs`: Round 6 through Round 8 transitions |
| Committed triple finalization before presign equations | Full | `src/driver.rs`: Round 8 and Round 9 transitions |
| Output only after `e` and `alpha`/`beta` exchanges | Full | `src/driver.rs`: Round 9 through Round 11 transitions |
| Bounded secret-state stack ownership | Full | `src/driver.rs`: boxed OT-extension, random-OT, and MTA states |
| Deterministic new/new driver plus purpose-built online signature vector | Full | `src/driver.rs`: `fixed_driver_completes_new_new_online_signature` |
| Canonical numeric wire registry, bounded encoding, and strict decoder | Full | `src/codec.rs`: fixed header and role/round registry, exact per-round widths, 49,228-byte ceiling, role-specific decode functions, and canonical field constructors |
| Encoded new/new semantic replay | Full | `src/codec.rs`: `every_fixed_round_round_trips_and_drives_new_new` encodes and decodes every peer message before advancing |
| Parser mutation and fuzz corpus | Partial | Header role, round, flags, length, and trailing-byte rejection are tested; broader body mutation and fuzz coverage remain open |
| Production Client and SigningWorker Wasm adapters use this driver | Full | `wasm/router_ab_ecdsa_presign_client` and `wasm/router_ab_ecdsa_signing_worker`; the cross-Wasm distributed suite completes all rounds |
| Persistence-backed exactly-once consumption | Partial | `router-ab-ecdsa-pool` defines the storage-independent contract; concrete Client and SigningWorker adapters remain open |

## Frozen deterministic vector

The deterministic native new/new test completes presigning, computes the
purpose-built Client online share, finalizes it with the purpose-built
SigningWorker path, and freezes the SHA-256 digest of the resulting signature:

`32d1804ed92cfb5fec40f4efe76bff13d75f26e5ab209b05094c867282aa918c`

This vector detects accidental protocol drift. It establishes deterministic
behavior for the selected inputs; it is not a security proof or a substitute
for the Phase D oracle and malformed-message corpus.

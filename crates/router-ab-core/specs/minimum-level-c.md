# Minimum Level C Verification

Minimum Level C is the first production correctness level. It protects server
blindness and transcript consistency. It does not prove algebraic correctness of
the derived account relation.

## Claim

Minimum Level C verifies that all delivered packages and signer receipts bind to
one transcript:

- same candidate id
- same request kind
- same correctness level
- same account scope
- same root-share epoch
- same ceremony id
- same Router identity
- same Signer A identity
- same Signer B identity
- same client identity
- same relayer identity

It also verifies that client material is delivered only to the client and
relayer material is delivered only to the designated relayer.

## Verifier

The verifier can be:

- Router before forwarding final packages
- relayer before opening relayer material
- client before opening client material
- an offline audit tool

All verifiers must use the same deterministic verification algorithm.

## Inputs

`verify_minimum_level_c_v1` takes:

- `DerivationContext`
- `TranscriptBinding`
- Signer A authenticated receipt
- Signer B authenticated receipt
- client delivery package commitments
- relayer delivery package commitments
- replay-cache decision for `ceremony_id`
- expected recipient identities

## Evidence V1

Evidence V1 contains:

- `evidence_version`
- `correctness_level = minimum_level_c`
- `context_digest`
- `transcript_digest`
- `signer_a_receipt_digest`
- `signer_b_receipt_digest`
- `client_package_commitments`
- `relayer_package_commitments`
- `replay_cache_key`

Evidence V1 is public.

## Signer Receipt V1

Each signer receipt contains:

- receipt version
- signer role
- signer identity
- accepted transcript digest
- accepted root-share epoch
- output package commitment digests created by that signer
- authenticated-envelope proof or receipt signature

Signer A must sign as Signer A. Signer B must sign as Signer B. Duplicated
signer identities are invalid.

## Verification Algorithm

`verify_minimum_level_c_v1`:

1. validate context fields
2. encode context V1
3. compute context digest V1
4. compute transcript digest V1
5. check evidence context digest equals computed context digest
6. check evidence transcript digest equals computed transcript digest
7. check Signer A receipt role and identity match transcript
8. check Signer B receipt role and identity match transcript
9. check Signer A and Signer B identities differ
10. check both signer receipts accepted the same transcript digest
11. check both signer receipts accepted the same root-share epoch
12. check client package commitments use recipient role `client`
13. check client package commitments use the transcript client identity
14. check relayer package commitments use recipient role `relayer`
15. check relayer package commitments use the transcript relayer identity
16. check all package commitments bind the same transcript digest
17. check replay cache accepted the ceremony id for this transcript
18. return accepted evidence

## Rejection Cases

Minimum Level C rejects:

- malformed context
- malformed transcript
- unknown evidence version
- wrong correctness level
- duplicate Signer A/B identity
- signer receipt under wrong role
- signer receipt under wrong identity
- signer receipt for different transcript digest
- signer receipt for different root-share epoch
- package commitment for wrong recipient role
- package commitment for wrong recipient identity
- package commitment for different transcript digest
- replayed ceremony id with changed bound fields
- unauthenticated signer receipt

## Residual Correctness Risk

Minimum Level C can accept transcript-consistent bad output if a malicious
signer produces a bad encrypted output share and the candidate does not include
public-share correctness evidence.

Mitigations:

- recipient-side opening detects unusable delivery material
- address verification gates root activation
- public-share-binding hardening adds group relation checks
- vectors must document accepted and rejected bad-output cases

## Address Verification Gate

For registration and refresh, production activation requires address
verification evidence after recipient opening. The activation gate checks that
the opened material corresponds to the expected account public key or a
candidate-specific verification relation.

Minimum Level C evidence alone is insufficient for production root activation.

## Error Mapping

| Failure | Error code |
| --- | --- |
| malformed context | `MalformedInput` |
| unknown evidence version | `UnsupportedVersion` |
| wrong correctness level | `CorrectnessLevelMismatch` |
| duplicated signer identity | `DuplicateSignerIdentity` |
| signer receipt mismatch | `SignerReceiptMismatch` |
| root epoch mismatch | `RootEpochMismatch` |
| transcript mismatch | `TranscriptMismatch` |
| recipient mismatch | `RecipientMismatch` |
| replayed changed ceremony | `ReplayMismatch` |
| unauthenticated receipt | `UnauthenticatedEnvelope` |
| package commitment mismatch | `PackageCommitmentMismatch` |

The Rust error enum must add these codes before implementation.

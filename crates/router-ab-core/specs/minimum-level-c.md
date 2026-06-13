# Minimum Level C Verification

Minimum Level C is the first production correctness level. It protects server
blindness and transcript consistency. It does not prove algebraic correctness of
the derived account relation.

## Claim

Minimum Level C verifies that all delivered packages and deriver receipts bind to
one transcript:

- same candidate id
- same request kind
- same correctness level
- same account scope
- same root-share epoch
- same ceremony id
- same Router identity
- same Deriver A identity
- same Deriver B identity
- same client identity
- same SigningWorker identity

It also verifies that client material is delivered only to the client and
SigningWorker material is delivered only to the active SigningWorker.

## Verifier

The verifier can be:

- Router before forwarding final packages
- SigningWorker before opening SigningWorker material
- client before opening client material
- an offline audit tool

All verifiers must use the same deterministic verification algorithm.

## Inputs

`verify_minimum_level_c_v1` takes:

- `DerivationContext`
- `TranscriptBinding`
- Deriver A authenticated receipt
- Deriver B authenticated receipt
- client delivery package commitments
- SigningWorker delivery package commitments
- replay-cache decision for `ceremony_id`
- expected recipient identities

## Evidence V1

Evidence V1 contains:

- `evidence_version`
- `correctness_level = minimum_level_c`
- `context_digest`
- `transcript_digest`
- `deriver_a_receipt_digest`
- `deriver_b_receipt_digest`
- `client_package_commitments`
- `signing_worker_package_commitments`
- `replay_cache_key`

Evidence V1 is public.

## Deriver Receipt V1

Each deriver receipt contains:

- receipt version
- deriver role
- deriver identity
- accepted transcript digest
- accepted root-share epoch
- output package commitment digests created by that deriver
- authenticated-envelope proof or receipt signature

Deriver A must sign as Deriver A. Deriver B must sign as Deriver B. Duplicated
deriver identities are invalid.

## Verification Algorithm

`verify_minimum_level_c_v1`:

1. validate context fields
2. encode context V1
3. compute context digest V1
4. compute transcript digest V1
5. check evidence context digest equals computed context digest
6. check evidence transcript digest equals computed transcript digest
7. check Deriver A receipt role and identity match transcript
8. check Deriver B receipt role and identity match transcript
9. check Deriver A and Deriver B identities differ
10. check both deriver receipts accepted the same transcript digest
11. check both deriver receipts accepted the same root-share epoch
12. check client package commitments use recipient role `client`
13. check client package commitments use the transcript client identity
14. check SigningWorker package commitments use recipient role `SigningWorker`
15. check SigningWorker package commitments use the transcript SigningWorker
    identity
16. check all package commitments bind the same transcript digest
17. check replay cache accepted the ceremony id for this transcript
18. return accepted evidence

## Rejection Cases

Minimum Level C rejects:

- malformed context
- malformed transcript
- unknown evidence version
- wrong correctness level
- duplicate Deriver A/B identity
- deriver receipt under wrong role
- deriver receipt under wrong identity
- deriver receipt for different transcript digest
- deriver receipt for different root-share epoch
- package commitment for wrong recipient role
- package commitment for wrong recipient identity
- package commitment for different transcript digest
- replayed ceremony id with changed bound fields
- unauthenticated deriver receipt

## Residual Correctness Risk

Minimum Level C can accept transcript-consistent bad output if a malicious
deriver produces a bad encrypted output share and the candidate does not include
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
| duplicated deriver identity | `DuplicateSignerIdentity` |
| deriver receipt mismatch | `SignerReceiptMismatch` |
| root epoch mismatch | `RootEpochMismatch` |
| transcript mismatch | `TranscriptMismatch` |
| recipient mismatch | `RecipientMismatch` |
| replayed changed ceremony | `ReplayMismatch` |
| unauthenticated receipt | `UnauthenticatedEnvelope` |
| package commitment mismatch | `PackageCommitmentMismatch` |

The Rust error enum must add these codes before implementation.

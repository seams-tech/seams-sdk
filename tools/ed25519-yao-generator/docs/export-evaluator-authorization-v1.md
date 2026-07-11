# Export Evaluator Authorization V1

Status: normative construction-independent host-reference contract.

This document freezes the Phase 1 requirement that Deriver A and Deriver B
independently accept the same explicit Ed25519 seed-export authorization before
one export evaluation begins. It defines signed host-reference acceptance
capabilities and their typed composition. It does not define production key
distribution, transport, durable nonce reservation, a selected P0-P3 protocol,
or a production constant-time claim.

## 1. Required state chain

```text
canonical export request
  + authenticated registered store resolution
  + ordered A/B provenance pair
  + one-use execution identity
  + trusted role-distinct A/B acceptance authorities
    -> verified Deriver A acceptance
    -> verified Deriver B acceptance
    -> ordered verified acceptance pair
    -> one export evaluation
    -> output commitment with authorization unconsumed
    -> Client release with authorization consumed
```

The evaluator session MUST NOT accept a raw authorization digest or a single
generic evidence slot. It requires one verified A capability and one verified B
capability. Role-specific Rust types make a duplicate-role or swapped-role pair
unrepresentable. Pair construction rejects reuse of the same raw verifying key,
and session admission consumes the pair by value so one Rust capability cannot
admit two evaluations.

## 2. Trusted authorities

Each role authority contains:

- the fixed role tag;
- the Deriver key epoch committed by the request context;
- a non-weak Ed25519 verifying key;
- a role-separated SHA-256 key digest.

The authority-key digest preimage is LP32:

1. `seams/router-ab/ed25519-yao/export-authorization-authority-key-digest/v1`;
2. role tag (`0x01` for A or `0x02` for B);
3. key epoch as BE64;
4. 32-byte verifying key.

The trusted authority pair rejects reuse of the same verifying key for both
roles. Export issuance owns the trusted pair. A verified acceptance pair created
under substituted keys fails even when an attacker coherently changes the
statement metadata and re-signs both statements.

Production authority discovery and key rotation are boundary responsibilities.
The host model assumes the trusted pair came from independently administered,
authenticated configuration.

## 3. Admission time

Each role records a nonzero `checked_at_unix_ms`. Acceptance fails when
`checked_at_unix_ms` is greater than the request expiry committed by the request
context. Durable clock rollback and global nonce uniqueness remain Phase 7
requirements.

## 4. Role acceptance statement

The canonical LP32 statement field order is:

1. `seams/router-ab/ed25519-yao/export-authorization-acceptance/v1`;
2. protocol ID;
3. export request tag `0x05`;
4. role tag;
5. Deriver ID;
6. Deriver key epoch as BE64;
7. role-separated authority-key digest;
8. `checked_at_unix_ms` as BE64;
9. request ID;
10. replay nonce;
11. request expiry as BE64;
12. Client recipient public key;
13. request-context digest;
14. authorization digest;
15. final transcript digest;
16. ordered provenance-pair digest;
17. digest of the exact store-authority-signed resolution bytes;
18. store-authority key epoch as BE64;
19. store-authority key digest;
20. active registered-state version as BE64;
21. registered Ed25519 public key;
22. one-use execution ID;
23. that role's provenance-statement digest;
24. accepted decision tag `0x01`.

Each role signs these exact bytes with Ed25519. Strict verification produces a
move-only role capability. Invalid signatures, weak keys, wrong role epochs,
expired requests, registered-key mismatch, or store/provenance mismatch fail
before evaluation.

The signed-artifact digest is SHA-256 over LP32:

1. `seams/router-ab/ed25519-yao/export-authorization-acceptance-digest/v1`;
2. exact statement bytes;
3. exact 64-byte signature.

## 5. Ordered pair

The acceptance pair encoding is LP32:

1. `seams/router-ab/ed25519-yao/export-authorization-acceptance-pair/v1`;
2. Deriver A signed-artifact digest;
3. Deriver B signed-artifact digest.

The pair digest is SHA-256 over LP32:

1. `seams/router-ab/ed25519-yao/export-authorization-acceptance-pair-digest/v1`;
2. the exact pair encoding.

Pair construction requires equality of the complete common binding: request,
replay nonce, expiry, recipient key, authorization, transcript, provenance pair,
signed store resolution, store authority, active state version, registered key,
and one-use execution ID. Role-local timestamps may differ, but both must be no
later than expiry.

The pair digest occupies the export semantic evaluation-evidence field and is
retained unchanged in the output-committed and released receipt encodings.

## 6. Evaluator and lifecycle rules

The accepted evaluator performs exactly one export-family evaluation with one A
invocation, one B invocation, and one ideal seed-share sample. It accepts only
`y_client` and `y_server` inputs for each role. No `tau` input belongs to export.

The evaluator reconstructs the host-only reference seed, verifies that its RFC
8032 public key equals the authenticated registered identity, samples the exact
A/B seed-share pair, and commits the two Client packages. Output commitment
leaves export authorization unconsumed. Client release consumes authorization.
Uncertainty and redelivery retain the exact package, share, acceptance-pair, and
receipt identities with zero reevaluation.

An admitted evaluation failure burns the request and one-use execution identity
while retaining the authenticated registered state. Durable crash recovery and
global replay protection remain Phase 7 work.

## 7. Security boundary

This contract establishes host-reference signature verification and exact
binding. Its trusted computing base includes SHA-256 collision resistance,
Ed25519 strict-verification correctness and unforgeability, trusted A/B authority
distribution, and a trustworthy admission clock.

The clear export reference deliberately uses variable-time host arithmetic and
temporarily reconstructs the seed. The generator crate is forbidden on WASM and
excluded from production dependency closures. These vectors provide no native
or Worker constant-time evidence.

Recipient encryption, package authentication, selected-profile input
consistency, output privacy, transport authentication, durable replay, and
P0-P3 protocol security remain later-phase obligations.

The `authorization_digest` authenticates an opaque boundary record. This host
contract does not parse or validate the record's policy grant, actor,
step-up-authentication claims, scope, or revocation state. The request boundary
must validate those claims before A and B sign their acceptances; the signatures
establish agreement on the resulting canonical record digest, not correctness
of the record's contents.

## 8. Canonical corpus

`vectors/ed25519-yao-export-evaluator-authorization-v1.json` contains one
canonical successful case. It names the corresponding ceremony, provenance,
evaluation-input party-view, semantic-lifecycle, and export-delivery cases. It
commits both authority keys, both signed role statements, the ordered pair, the
one-evaluation plan, and the exact output-committed and released receipt
encodings and digests with consumed authorization. The independent verifier
reconstructs both signed acceptances, the pair, both receipt digests, and their
request/provenance/execution/registered-key bindings.

Mutation tests cover signature failure, role-key reuse, coherent authority
substitution, execution-ID splice, expiry, canonical byte drift, and receipt
encoding/digest drift. Production cryptographic and operational claims remain
explicitly excluded.

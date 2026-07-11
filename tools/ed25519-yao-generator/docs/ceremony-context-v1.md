# Canonical ceremony context v1

Status: fixed host-only byte contract.

This document freezes the public request, authorization, and transcript DAG used by the Ed25519 Yao reference artifacts. It defines canonical encodings and digest dependencies. It does not authenticate authorization records, transport bindings, artifact suites, role inputs, or network peers.

## Common rules

- Every encoded value uses `BE32(length) || value`, called LP32 below.
- Encodings are ordered concatenations of LP32 values. Reordering, omission, duplication, truncation, and trailing bytes are invalid.
- Digests are SHA-256 over the exact canonical encoding bytes.
- Text identifiers are nonempty visible ASCII bytes `0x21..0x7e`.
- Versions, epochs, and expiry values are nonzero unsigned 64-bit integers encoded in big-endian order.
- `protocolVersion` is exactly `BE64(1)`.
- Replay and transcript nonces are distinct 32-byte domain types.
- The client ephemeral public key is exactly 32 bytes.
- Opaque authorization-record, registration-intent, package-set, replacement-credential, transport-binding, and artifact-suite digest slots are nonzero 32-byte values.

The fixed request mapping is:

| Request | Tag | Circuit ID | Recipient plan/tag | Output package/tag | Evaluation provenance |
| --- | ---: | --- | --- | --- | --- |
| registration | `0x01` | `ed25519_yao_activation_v1` | `activation_family` / `0x01` | `activation_scalar_shares` / `0x01` | yes |
| activation | `0x02` | `ed25519_yao_activation_v1` | `activation_continuation` / `0x02` | `activation_scalar_shares` / `0x01` | no |
| recovery | `0x03` | `ed25519_yao_activation_v1` | `activation_family` / `0x01` | `activation_scalar_shares` / `0x01` | yes |
| refresh | `0x04` | `ed25519_yao_activation_v1` | `activation_family` / `0x01` | `activation_scalar_shares` / `0x01` | yes |
| export | `0x05` | `ed25519_yao_export_v1` | `export` / `0x03` | `export_seed_shares` / `0x02` | yes |

The textual recipient-plan and output-package fields in the JSON corpus are audit metadata. The canonical request encoding commits their one-byte tags derived from the request kind.

## Digest DAG

The only valid dependency order is:

1. `PublicRequestContext`
2. branch-specific `Authorization`, which embeds `SHA-256(PublicRequestContext)`
3. `CeremonyTranscript`, which embeds both prior digests

`CeremonyValidatedDagV1` is the sealed host type produced from matching instances of all three layers. It rejects branch mismatch, request-context digest mismatch, and authorization digest mismatch. Downstream provenance accepts this witness instead of independently supplied digests.

Ciphertexts, recipient envelopes, AAD digests, provenance statements, proof digests, and transcript digests are excluded from transcript inputs when their inclusion would create a circular dependency. Their independently committed suite or transport roots occupy the explicit opaque digest slots.

## Public request context

Domain:

`seams/router-ab/ed25519-yao/public-request-context/v1`

The encoding is LP32 of the domain followed by each label and value as two LP32 fields, in this exact order:

1. `protocolVersion`, `BE64(1)`
2. `requestKind`, one request tag
3. `requestId`, visible ASCII
4. `replayNonce`, 32 bytes
5. `accountId`, visible ASCII
6. `walletId`, visible ASCII
7. `sessionId`, visible ASCII
8. `organizationId`, visible ASCII
9. `projectId`, visible ASCII
10. `environmentId`, visible ASCII
11. `signingRootId`, visible ASCII
12. `signingRootVersion`, nonzero BE64
13. `chainTarget`, visible ASCII
14. `rootShareEpoch`, nonzero BE64
15. `routerId`, visible ASCII
16. `deriverSetId`, visible ASCII
17. `deriverAId`, visible ASCII
18. `deriverAKeyEpoch`, nonzero BE64
19. `deriverBId`, visible ASCII
20. `deriverBKeyEpoch`, nonzero BE64
21. `signingWorkerId`, visible ASCII
22. `signingWorkerKeyEpoch`, nonzero BE64
23. `clientEphemeralPublicKey`, 32 bytes
24. `recipientPlan`, one derived tag
25. `outputPackageKind`, one derived tag
26. `requestExpiry`, nonzero BE64

Both `accountId` and `walletId` are mandatory. Router, Deriver-set, chain-target, tenancy, session, signing-root, role identity, and role-key-epoch metadata are bound before authorization.

## Branch authorization

Each authorization starts with its branch domain, followed by labeled `requestKind` and `publicRequestContextDigest` fields. It then appends the exact branch fields below.

| Branch | Domain suffix | Ordered branch fields |
| --- | --- | --- |
| registration | `authorization/registration/v1` | `authorizationRecordDigest`, `registrationIntentDigest` |
| activation | `authorization/activation/v1` | `authorizationRecordDigest`, `originRequestKind`, `originRequestContextDigest`, `originTranscriptDigest`, `packageSetDigest`, `activationEpoch` |
| recovery | `authorization/recovery/v1` | `authorizationRecordDigest`, `replacementCredentialBindingDigest` |
| refresh | `authorization/refresh/v1` | `authorizationRecordDigest`, `currentDeriverAInputStateEpoch`, `nextDeriverAInputStateEpoch`, `currentDeriverBInputStateEpoch`, `nextDeriverBInputStateEpoch` |
| export | `authorization/export/v1` | `authorizationRecordDigest`, `registeredEd25519PublicKey` |

Each full domain is prefixed by `seams/router-ab/ed25519-yao/`.

Refresh requires each next role input-state epoch to be strictly greater than its corresponding current epoch. Export requires a canonical, nonidentity, torsion-free compressed Edwards25519 point.

Activation accepts a sealed `CeremonyActivationOriginV1`. This witness can only be narrowed from a coherent registration, recovery, or refresh DAG. Activation and export DAGs are ineligible. The origin request context must differ from the activation-control request context. The origin kind and both origin digests are derived from the witness and encoded; callers cannot supply them independently.

## Ceremony transcript

Domain:

`seams/router-ab/ed25519-yao/ceremony-transcript/v1`

The exact labeled field order is:

1. `protocolVersion`, `BE64(1)`
2. `protocolId`, `router_ab_ed25519_yao_v1`
3. `requestKind`, one request tag
4. `circuitId`, derived from the request kind
5. `publicRequestContextDigest`, 32 bytes
6. `authorizationDigest`, 32 bytes
7. `transcriptNonce`, 32 bytes
8. `transportBindingDigest`, nonzero 32 bytes
9. `artifactSuiteDigest`, nonzero 32 bytes

The transcript constructor verifies the request branch and both prior digest edges before producing these bytes.

## Provenance coupling

Evaluation provenance is defined only for registration, recovery, refresh, and export. Its ceremony-binding encoding includes the provenance request tag before the three ceremony digests. The tag must equal the outer statement branch. Branch-specific common builders reject a sealed ceremony witness from another branch. Activation-control DAGs cannot produce an evaluation-provenance binding.

## Portable corpus and evidence limits

`vectors/ed25519-yao-ceremony-context-v1.json` contains exactly five cases in registration, activation, recovery, refresh, and export order. Each case includes source values plus exact request, authorization, and transcript encodings and digests. The activation case links to the coherent registration case.

The Rust generator and the stdlib-only Python verifier independently rebuild every encoding and digest. Rust coverage accepts coherent registration, recovery, and refresh activation origins. Mutation coverage includes protocol-version drift, invalid field shapes, branch mismatch, refresh epoch regression, invalid registered keys, invalid activation origin kinds, current-context origin reuse, digest-edge splicing, and provenance ceremony-kind or digest-tuple splicing. The independent provenance verifier cross-links every evaluation branch to the matching reconstructed ceremony case.

All values in this reference corpus are public synthetic data. Constant-time behavior, active-secure Yao, authenticated deployment policy, production replay persistence, authorization-record verification, and artifact/proof verification remain outside this byte-contract claim.

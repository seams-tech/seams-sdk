# Ed25519 Yao Role-Input Provenance Statement V1

Status: **Phase 1 proof-system-neutral contract; production use blocked**

This document freezes the candidate semantic shape and canonical outer bytes for
an Ed25519 Yao role-input provenance statement. It does not select a commitment
scheme, proof system, active Yao compiler, OT construction, circuit artifact, or
production root-custody mechanism. A statement digest proves only which bytes
were committed. The Phase 6 evidence verifier must establish the relations
described here.

The statement covers Yao evaluations for registration, recovery, refresh, and
authorized export. Activation is excluded from the evaluation request kinds.
Activation consumes previously committed activation-family packages and performs
zero Yao evaluations. The controlling sources are **Fixed Circuit Families** in
`docs/yaos-ab.md` and **Product Operation To Ideal Functionality To Circuit
Mapping** in `docs/router-a-b-SPEC.md`.

## 1. Source boundary

The controlling requirements are:

- `StableKeyDerivationContext` contains immutable key-affecting bytes, while
  request kind, circuit identity, authorization, transport, tickets, and epochs
  belong to `CeremonyTranscriptContext` (`docs/yaos-ab.md`, **Stable Key Context
  and Ceremony Context**).
- The frozen role-local KDF consumes a 32-byte root, fixed role/source/output
  tags, and the stable-context binding digest (`docs/yaos-ab.md`, **Stable Key
  Context and Ceremony Context**).
- The Yao-only application binding is the SHA-256 digest of one frozen LP32
  encoding over `walletId`, `nearEd25519SigningKeyId`, `signingRootId`, and a
  positive `u32` `keyCreationSignerSlot` (`src/application_binding.rs`).
- Active 2PC must be augmented with evidence connecting supplied inputs to the
  provisioned role root, wallet/key identity, derivation context/path, root
  epoch, request kind, client envelope, and authorization
  (`docs/yaos-ab.md`, **Input Provenance**).
- Registration requires an anti-bias analysis, and recovery and refresh require
  continuity with the registered public identity (`docs/yaos-ab.md`, **Input
  Provenance**).
- The production security claim depends on an approved input-provenance proof
  and remains limited to Router plus at most one malicious Deriver under no A+B
  collusion (`docs/yaos-ab.md`, **Goal**).

The host reference already freezes the stable-context bytes and binding at
`src/context.rs:5-15,107-162` and the synthetic KDF at
`src/kdf.rs:12-40,182-312`. The application-binding encoder and its golden
digest are implemented at `src/application_binding.rs` and
`tests/application_binding.rs`. The oracle accepts raw role contribution
values at `src/lib.rs:137-159,257-340`. It has no production root record, input
commitment, epoch, authorization, or provenance-evidence type.

## 2. Scope and claim boundary

This contract freezes:

- disjoint evaluation request-kind tags;
- role and circuit-family tags;
- proof-system-neutral typed statement slots;
- LP32 field framing and canonical field order;
- statement, A/B pair, client-envelope-set, and artifact-wrapper digest domains;
- root-epoch and role-input-state-epoch meanings;
- semantic relations that later evidence must establish;
- registration anti-bias acceptance requirements.

This contract does not freeze:

- the bytes inside a root, input, envelope, continuity, or anti-bias artifact;
- the cryptographic commitment or proof carried by an artifact;
- the evidence-envelope format used by the selected Phase 6 construction;
- final active circuit and input-schema digest values;
- production same-root recovery custody and continuity proof;
- refresh delta generation, active transition proof, and distributed cutover
  realization;
- production persistence, transport, or public-leakage expansion.

The full statement and its artifacts do not become public merely because this
document defines canonical bytes. Existing party-view and forbidden-leakage
rules continue to control visibility (`docs/yaos-ab.md`, **Goal**, plus the
**Forbidden leakage** and **Value-custody matrix** sections of
`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`).

## 3. Primitive encodings

### 3.1 LP32

For one byte string `x`:

```text
LP32(x) = BE32(len(x)) || x
```

`len(x)` is the byte length in the range `0..=2^32-1`. Encoders reject a value
whose length cannot be represented by `BE32`. Decoders reject truncation,
trailing bytes, duplicate fields, alternate field order, and non-minimal outer
containers. Every field below is emitted as exactly one `LP32` value, including
one-byte tags, fixed-width integers, digests, and nested encodings.

This convention matches the existing Router A/B reference framing at
`crates/router-ab-core/src/derivation/context.rs:245-259,315-324` and
`crates/router-ab-core/src/derivation/transcript.rs:384-432`. The legacy Router
candidate and request enums are not reused.

### 3.2 Fixed-width values

```text
Digest32       = exactly 32 bytes
Ed25519Point32 = exactly 32 bytes in canonical compressed Edwards encoding
Epoch64        = BE64(nonzero unsigned integer)
ParticipantId  = BE16(nonzero unsigned integer)
Tag8           = exactly one byte
```

An all-zero byte string is never an absence sentinel. Absence is represented by
a branch type that lacks the field. Production constructors recompute a digest
or resolve it from an authenticated record; they do not accept an arbitrary
caller-provided `Digest32` as evidence.

### 3.3 Frozen domains

```text
STABLE_SCOPE_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/stable-scope/v1")

CEREMONY_BINDING_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/ceremony-binding/v1")

ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/role-input-snapshot/v1")

REGISTRATION_BRANCH_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/registration-branch/v1")

RECOVERY_BRANCH_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/recovery-branch/v1")

REFRESH_BRANCH_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/refresh-branch/v1")

EXPORT_BRANCH_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance/export-branch/v1")

STATEMENT_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/role-input-provenance-statement/v1")

STATEMENT_DIGEST_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/role-input-provenance-statement-digest/v1")

PAIR_ENCODING_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/role-input-provenance-pair/v1")

PAIR_DIGEST_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/role-input-provenance-pair-digest/v1")

CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/client-envelope-commitment-set/v1")

ARTIFACT_DIGEST_DOMAIN_V1 =
  ASCII("seams/router-ab/ed25519-yao/provenance-artifact-digest/v1")
```

### 3.4 Frozen tags and identifiers

The protocol identifier is the exact ASCII value
`router_ab_ed25519_yao_v1`, matching `crates/ed25519-yao/src/ids.rs:1-2`.

Lifecycle tags reserve one namespace for all five lifecycle kinds:

| Lifecycle kind | Tag    | Valid in an evaluation statement |
| -------------- | ------ | -------------------------------- |
| Registration   | `0x01` | yes                              |
| Activation     | `0x02` | no; reserved                     |
| Recovery       | `0x03` | yes                              |
| Refresh        | `0x04` | yes                              |
| Export         | `0x05` | yes                              |

Role tags match the frozen contribution-KDF role tags at
`src/kdf.rs:20-24`:

| Role      | Tag    |
| --------- | ------ |
| Deriver A | `0x01` |
| Deriver B | `0x02` |

Circuit-family tags match the current draft-manifest family bytes at
`crates/ed25519-yao/src/manifest.rs:11-17`:

| Circuit family | Tag    | Exact circuit identifier    |
| -------------- | ------ | --------------------------- |
| Activation     | `0x01` | `ed25519_yao_activation_v1` |
| Export         | `0x02` | `ed25519_yao_export_v1`     |

The production statement binds the final active `CircuitDigest32` and
`InputSchemaDigest32`. The current crate provides distinct digest roles at
`crates/ed25519-yao/src/digest.rs:100-147`; their final values remain unfrozen.

Artifact-kind tags are:

| Artifact kind                              | Tag    |
| ------------------------------------------ | ------ |
| Role-root binding                          | `0x01` |
| Client-input binding                       | `0x02` |
| Server-input binding                       | `0x03` |
| Combined role-input binding                | `0x04` |
| Client-envelope commitment                 | `0x05` |
| Registration anti-bias evidence            | `0x06` |
| Recovery same-root continuity evidence     | `0x07` |
| Refresh opposite-delta transition evidence | `0x08` |

## 4. Artifact digest wrapper

The outer statement binds arbitrary Phase 6 artifacts through one canonical
wrapper:

```text
ArtifactDigestV1(kind_tag, canonical_artifact_bytes) =
  SHA-256(
    LP32(ARTIFACT_DIGEST_DOMAIN_V1)
    || LP32(kind_tag[1])
    || LP32(canonical_artifact_bytes)
  )
```

This SHA-256 wrapper supplies collision-resistant byte binding only. It does not
supply hiding, knowledge soundness, root provenance, input consistency, or
anti-bias by itself.

The selected artifact construction must satisfy all applicable requirements:

- computational hiding for every root or secret-input value;
- computational binding to one canonical value and one statement scope;
- canonical parsing with no alternate encoding of the same artifact;
- role, stable-context, wallet/key/path, request, transcript, circuit, epoch, and
  authorization binding wherever the artifact relation uses those values;
- fresh randomized commitments when a stable commitment would add linkability
  outside the approved party view;
- proof of possession or knowledge where a bare commitment would let an attacker
  bind an unavailable value;
- no direct `SHA-256(root)` or `SHA-256(secret input tuple)` substitute;
- explicit erasure and one-use behavior for commitment randomness when required
  by the selected active protocol.

The artifact suite, canonical artifact encoders, verification keys, and proof
bytes remain Phase 6 decisions. The eventual evidence envelope must bind its
proof-suite identity and verification-key identity to `StatementDigestV1`.

## 5. Typed statement schema

The semantic types use private fields and branch-specific constructors. Raw
request bodies, database records, and proof objects are parsed once at their
boundary. Core verification never accepts an untagged property bag.

```rust
enum YaoEvaluationRequestKindV1 {
    Registration,
    Recovery,
    Refresh,
    Export,
}

enum ProvenanceRoleV1 {
    DeriverA,
    DeriverB,
}

enum RoleInputProvenanceStatementV1 {
    Registration(RegistrationRoleInputStatementV1),
    Recovery(RecoveryRoleInputStatementV1),
    Refresh(RefreshRoleInputStatementV1),
    Export(ExportRoleInputStatementV1),
}

struct RegistrationRoleInputStatementV1 {
    common: RegistrationCommonV1,
    branch: RegistrationBranchV1,
}

struct RecoveryRoleInputStatementV1 {
    common: RecoveryCommonV1,
    branch: RecoveryBranchV1,
}

struct RefreshRoleInputStatementV1 {
    common: RefreshCommonV1,
    branch: RefreshBranchV1,
}

struct ExportRoleInputStatementV1 {
    common: ExportCommonV1,
    branch: ExportBranchV1,
}
```

Each `*CommonV1` constructor fixes its request tag and permitted circuit family.
Callers never provide either mapping. Activation has no statement variant.

### 5.1 Stable KDF scope

```rust
struct StableKdfScopeV1 {
    application_binding_digest: ApplicationBindingDigest32,
    participant_ids: NormalizedParticipantIds,
    stable_context_binding_digest: StableContextBindingDigest32,
}
```

These are the complete immutable KDF fields. They contain no request,
authorization, ticket, deployment, transport, circuit, credential version, or
mutable epoch value.

Exact encoding order:

```text
StableKdfScopeEncodingV1 =
    LP32(STABLE_SCOPE_ENCODING_DOMAIN_V1)
 || LP32(application_binding_digest[32])
 || LP32(BE16(participant_low))
 || LP32(BE16(participant_high))
 || LP32(stable_context_binding_digest[32])
```

`participant_low < participant_high`; both are nonzero. The verifier recomputes
the frozen `StableKeyDerivationContextV1` and its binding from
`application_binding_digest` and these participant identifiers.

The application binding is frozen separately:

```text
application_binding_domain =
  ASCII("seams/router-ab/ed25519-yao/application-binding/v1")

Ed25519YaoApplicationBindingEncodingV1 =
    LP32(application_binding_domain)
 || LP32(ASCII("walletId"))
 || LP32(UTF8(wallet_id))
 || LP32(ASCII("nearEd25519SigningKeyId"))
 || LP32(UTF8(near_ed25519_signing_key_id))
 || LP32(ASCII("signingRootId"))
 || LP32(UTF8(signing_root_id))
 || LP32(ASCII("keyCreationSignerSlot"))
 || LP32(BE32(key_creation_signer_slot))

application_binding_digest =
  SHA-256(Ed25519YaoApplicationBindingEncodingV1)
```

All three identifier strings contain one or more visible ASCII bytes in the
inclusive range `0x21..=0x7e`. Spaces, control bytes, non-ASCII code points,
trimming, and Unicode normalization are outside the version-one grammar. The
encoder preserves the exact validated bytes. Production construction must read
the values from authenticated SDK domain records through parsers that enforce
the same grammar. `key_creation_signer_slot` is a positive `u32` naming the
immutable slot used when the key identity was created. It never means a current
active/default slot or a new recipient slot. `nearAccountId`,
`signingRootVersion`, credential version, and every mutable epoch are
structurally absent. `nearAccountId` is excluded because an implicit NEAR account
identity is derived from the Ed25519 public key and would create a circular key
derivation input. The implementation is at `src/application_binding.rs`.

The golden facts are:

```text
wallet_id                    = "wallet-fixture"
near_ed25519_signing_key_id  = "ed25519ks_fixture"
signing_root_id              = "project-fixture:env-fixture"
key_creation_signer_slot     = 1
application_binding_digest   =
  b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121
stable_context_binding_for_participants_1_2 =
  b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655
```

The canonical preimage is 213 bytes. The complete golden encoding is committed in
`vectors/ed25519-yao-kdf-v1.json` and asserted at
`tests/application_binding.rs`.

The version-one derivation path is the fixed tuple of protocol identifier,
role tag, source tag, output tag, and stable-context binding used by the frozen
KDF. It has no caller-selected string or independent path digest. The later
provenance relation verifies those fixed tags directly.

### 5.2 Ceremony binding

```rust
struct CeremonyProvenanceBindingV1 {
    public_request_context_digest: PublicRequestContextDigest32,
    transcript_digest: CeremonyTranscriptDigest32,
    authorization_digest: AuthorizationDigest32,
    client_envelope_commitment_artifact_digest: ClientEnvelopeArtifactDigest32,
    client_envelope_set_digest: ClientEnvelopeSetDigest32,
}
```

Exact encoding order:

```text
CeremonyProvenanceBindingEncodingV1 =
    LP32(CEREMONY_BINDING_ENCODING_DOMAIN_V1)
 || LP32(public_request_context_digest[32])
 || LP32(transcript_digest[32])
 || LP32(authorization_digest[32])
 || LP32(client_envelope_commitment_artifact_digest[32])
 || LP32(client_envelope_set_digest[32])
```

The lifecycle-specific authorization encoder must always produce a digest.
Registration uses admitted registration authorization. Recovery, refresh, and
export use their distinct approved scopes. No zero or omitted authorization
slot exists.

The client-envelope-set digest is computed in fixed A/B order:

```text
ClientEnvelopeSetDigestV1 =
  SHA-256(
    LP32(CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1)
    || LP32(client_envelope_A_artifact_digest[32])
    || LP32(client_envelope_B_artifact_digest[32])
  )
```

The role statement carries its own envelope artifact digest and the common set
digest. The A/B pair verifier checks the set digest against both role-specific
artifact digests.

The transcript digest must have an acyclic dependency graph. It cannot depend on
the statement digest, pair digest, proof/evidence digest, encrypted envelope
ciphertext, or an AAD digest that depends on the transcript. This extends the
existing no-self-dependency rule in `docs/router-a-b-SPEC.md`, **Transcript
Binding**.

### 5.3 Role-input snapshot

```rust
struct RoleInputSnapshotV1<Role> {
    role_root_record_digest: RoleRootRecordDigest32<Role>,
    root_binding_artifact_digest: RootBindingArtifactDigest32<Role>,
    role_root_epoch: RoleRootEpochV1<Role>,
    role_input_state_record_digest: RoleInputStateRecordDigest32<Role>,
    role_input_state_epoch: RoleInputStateEpochV1<Role>,
    client_input_binding_artifact_digest: ClientInputArtifactDigest32<Role>,
    server_input_binding_artifact_digest: ServerInputArtifactDigest32<Role>,
    combined_role_input_binding_artifact_digest: CombinedInputArtifactDigest32<Role>,
}
```

`Role` is a sealed marker. Deriver A and Deriver B snapshots cannot be exchanged
through a generic constructor.

Exact encoding order:

```text
RoleInputSnapshotEncodingV1 =
    LP32(ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1)
 || LP32(role_root_record_digest[32])
 || LP32(root_binding_artifact_digest[32])
 || LP32(BE64(role_root_epoch))
 || LP32(role_input_state_record_digest[32])
 || LP32(BE64(role_input_state_epoch))
 || LP32(client_input_binding_artifact_digest[32])
 || LP32(server_input_binding_artifact_digest[32])
 || LP32(combined_role_input_binding_artifact_digest[32])
```

The role tag is carried by the enclosing statement and by every artifact's
verified relation. The snapshot encoder does not repeat it.

## 6. Lifecycle branches

### 6.1 Registration

```rust
struct RegistrationBranchV1<Role> {
    initial_snapshot: RoleInputSnapshotV1<Role>,
    registration_intent_digest: RegistrationIntentDigest32,
    anti_bias_evidence_artifact_digest: RegistrationAntiBiasArtifactDigest32,
}
```

```text
RegistrationBranchEncodingV1 =
    LP32(REGISTRATION_BRANCH_ENCODING_DOMAIN_V1)
 || LP32(RoleInputSnapshotEncodingV1(initial_snapshot))
 || LP32(registration_intent_digest[32])
 || LP32(anti_bias_evidence_artifact_digest[32])
```

Registration structurally lacks a registered public key and a before-state
snapshot. It starts from the unregistered public pre-state and establishes a new
public identity (`docs/yaos-ab.md`, **Fixed Circuit Families**). Its anti-bias
artifact is mandatory.

### 6.2 Recovery

```rust
struct RecoveryBranchV1<Role> {
    current_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32,
    same_root_evidence_artifact_digest: RecoveryContinuityArtifactDigest32,
}
```

```text
RecoveryBranchEncodingV1 =
    LP32(RECOVERY_BRANCH_ENCODING_DOMAIN_V1)
 || LP32(RoleInputSnapshotEncodingV1(current_snapshot))
 || LP32(registered_public_key[32])
 || LP32(same_root_evidence_artifact_digest[32])
```

The registered public key must be a canonical non-identity prime-subgroup point.
Version-one recovery rewraps the exact same logical 32-byte client derivation
root under the replacement credential binding. The stable context, all client
KDF contributions, both role roots, all effective server/account contributions,
both role-root epochs, and both role-input-state epochs remain byte-for-byte
unchanged. Credential and activation epochs advance in ceremony/persistence
state. An unavailable or suspected-compromised client root requires explicit
wallet rekey and a new Ed25519 identity; version one has no compensating
root-replacement branch.

The same-root evidence must bind the old and replacement credential envelopes to
the same logical client root and current snapshot, and must establish
`d_after = d_before` and `A_pub_after = A_pub_before` without export wires or
reconstruction by a server role. These semantics are frozen at
`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`,
**F_ed25519_recovery_v1** and **Recovery preservation proof and custody**.
Production protected custody, proof realization, signed receipts, and durable
transactions remain blocked.

### 6.3 Refresh

```rust
struct RefreshBranchV1<Role> {
    before_snapshot: RoleInputSnapshotV1<Role>,
    after_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32,
    continuity_evidence_artifact_digest: RefreshContinuityArtifactDigest32,
}
```

```text
RefreshBranchEncodingV1 =
    LP32(REFRESH_BRANCH_ENCODING_DOMAIN_V1)
 || LP32(RoleInputSnapshotEncodingV1(before_snapshot))
 || LP32(RoleInputSnapshotEncodingV1(after_snapshot))
 || LP32(registered_public_key[32])
 || LP32(continuity_evidence_artifact_digest[32])
```

The refresh artifact must bind nonzero canonical `delta_y` in `Z_(2^256)` and
`delta_tau` in `Z_l` and establish the fixed opposite-sign update:

```text
effective_y_server_A_next   = effective_y_server_A + delta_y mod 2^256
effective_y_server_B_next   = effective_y_server_B - delta_y mod 2^256
effective_tau_server_A_next = effective_tau_server_A + delta_tau mod l
effective_tau_server_B_next = effective_tau_server_B - delta_tau mod l
```

Both client contributions, both role roots, and both role-root epochs remain
unchanged. Each role-input-state epoch strictly advances. The evidence must
establish equality of joined `y`, joined `tau`, `d`, `a`, both signing bases,
both public points, and the registered public key.

The monotonic cutover is frozen as
`Active(current) -> Prepared -> OutputCommitted -> WorkerActivated -> Active(next)`
plus an old-epoch tombstone. Before `OutputCommitted`, abort discards staged
next-epoch state and leaves current active. At and after `OutputCommitted`, the
transition moves forward through exact ciphertext redelivery and idempotent
receipts; circuit re-evaluation, delta replacement, and old-epoch rollback are
forbidden. See `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`,
**F_ed25519_refresh_v1** and **Refresh delta generation, proof, and distributed
cutover**.
Production joint delta generation, active transition proof, and distributed
role-local transactions remain blocked.

### 6.4 Export

```rust
struct ExportBranchV1<Role> {
    current_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32,
}
```

```text
ExportBranchEncodingV1 =
    LP32(EXPORT_BRANCH_ENCODING_DOMAIN_V1)
 || LP32(RoleInputSnapshotEncodingV1(current_snapshot))
 || LP32(registered_public_key[32])
```

Export has no transition evidence or next epoch. Its distinct authorization
digest and export circuit family are mandatory. The authorized client must
reconstruct `d`, recompute the Ed25519 public key, and compare it with
`registered_public_key` (`docs/yaos-ab.md`, **Protocol-Generated Output
Sharing**).

## 7. Complete statement encoding

For each branch, the branch-specific common constructor supplies:

```rust
struct EvaluationStatementCommonV1<Role, Request> {
    stable_scope: StableKdfScopeV1,
    ceremony: CeremonyProvenanceBindingV1,
    final_circuit_digest: CircuitDigest32,
    input_schema_digest: InputSchemaDigest32,
}
```

Exact canonical order:

```text
RoleInputProvenanceStatementEncodingV1 =
    LP32(STATEMENT_ENCODING_DOMAIN_V1)
 || LP32(ASCII("router_ab_ed25519_yao_v1"))
 || LP32(request_kind_tag[1])
 || LP32(role_tag[1])
 || LP32(circuit_family_tag[1])
 || LP32(ASCII(exact_circuit_id))
 || LP32(final_circuit_digest[32])
 || LP32(input_schema_digest[32])
 || LP32(StableKdfScopeEncodingV1)
 || LP32(CeremonyProvenanceBindingEncodingV1)
 || LP32(lifecycle_branch_encoding)
```

The allowed mapping is fixed:

| Request tag  | Family tag | Circuit identifier          |
| ------------ | ---------- | --------------------------- |
| Registration | Activation | `ed25519_yao_activation_v1` |
| Recovery     | Activation | `ed25519_yao_activation_v1` |
| Refresh      | Activation | `ed25519_yao_activation_v1` |
| Export       | Export     | `ed25519_yao_export_v1`     |

Any other combination fails construction or parsing.

The digest is:

```text
StatementDigestV1 =
  SHA-256(
    LP32(STATEMENT_DIGEST_DOMAIN_V1)
    || LP32(RoleInputProvenanceStatementEncodingV1)
  )
```

## 8. A/B provenance pair

The pair is role-typed and ordered:

```rust
struct RoleInputProvenancePairV1 {
    deriver_a: DeriverAInputProvenanceStatementV1,
    deriver_b: DeriverBInputProvenanceStatementV1,
}
```

```text
RoleInputProvenancePairEncodingV1 =
    LP32(PAIR_ENCODING_DOMAIN_V1)
 || LP32(StatementDigestV1(deriver_a)[32])
 || LP32(StatementDigestV1(deriver_b)[32])

RoleInputProvenancePairDigestV1 =
  SHA-256(
    LP32(PAIR_DIGEST_DOMAIN_V1)
    || LP32(RoleInputProvenancePairEncodingV1)
  )
```

The pair verifier requires:

1. role A appears first and role B appears second;
2. roles are distinct and match every role-scoped record and artifact relation;
3. request kind, circuit family/id/digest, input-schema digest, stable scope,
   public-request-context digest, transcript digest, authorization digest, and
   client-envelope-set digest are identical;
4. each role carries its own client-envelope commitment artifact digest;
5. recomputing the client-envelope-set digest from A then B matches both
   statements;
6. role-root records belong to their respective independently administered role;
7. each role's root and role-input-state epochs equal its authoritative current
   snapshot for the lifecycle branch;
8. both client-input artifacts bind role-separated contributions to the same
   client derivation lineage and stable context;
9. lifecycle branch types match; registration intent and joint anti-bias
   evidence digests match for registration, while registered public keys and
   joint transition-evidence digests match for recovery or refresh;
10. recovery current snapshots match registered role state, and same-root
    evidence preserves both client contributions, both role roots, and both
    root/input-state epochs;
11. export registered public keys match, and refresh before/after pairs refer to
    the same registered key lineage while allowing distinct per-role epoch
    values;
12. neither statement digest, pair digest, nor artifact digest is reused as a
    secret contribution or randomized-output seed;
13. the active protocol, preprocessing ticket, peer frames, output artifacts,
    and terminal receipt bind the pair digest before output release.

The final condition becomes executable after the active protocol and ticket
formats are selected.

## 9. Epoch semantics

### 9.1 Role-root epoch

`RoleRootEpochV1<Role>` is a nonzero, per-role, monotonic `u64` identifying the
authenticated protected derivation-root record used by the provenance relation.
It is ceremony and persistence metadata. It never enters
`StableKeyDerivationContextV1` or the contribution KDF.

- Rewrapping identical logical root bytes under a new storage or wrapping key
  leaves `role_root_epoch` unchanged. The wrapping/storage key epoch changes in
  ceremony or persistence metadata.
- Replacing role-root material advances `role_root_epoch`.
- Root replacement changes the Ed25519 key and public identity while retaining
  the durable `walletId`; it requires an explicit wallet-rekey operation.
  Version-one recovery never replaces a derivation root.
- A caller and Router cannot choose a root record. The role-local store resolves
  exactly one record from the authenticated wallet/key/stable-scope binding.
- Restored, stale, missing, duplicated, or ambiguous root epochs fail closed.

### 9.2 Role-input-state epoch

`RoleInputStateEpochV1<Role>` is a separate nonzero, per-role, monotonic `u64`
identifying the persisted role-local contribution state committed by
`role_input_state_record_digest`.

- Registration establishes the first accepted role-input-state epoch.
- Activation leaves it unchanged because activation performs no evaluation.
- Export leaves it unchanged.
- Recovery leaves it unchanged because the same logical client root and every
  KDF/effective contribution remain unchanged. Credential and activation epochs
  advance separately.
- A successful refresh advances each role's input-state epoch strictly while
  leaving both role-root epochs unchanged.
- Refresh must preserve joined `y`, joined `tau`, `d`, and the registered public
  key across both roles.
- A before/after transition cannot reuse an epoch value or move backward.
- Before refresh `OutputCommitted`, abort discards staged next-epoch state and
  retains current. At and after that boundary, the cutover resumes forward
  through signed receipts, activates both next epochs, and tombstones both old
  epochs. Old-epoch rollback and cryptographic re-evaluation are forbidden.

Role-root and role-input-state epochs are independent between A and B. Their
values need not be numerically equal. A transition verifies each against that
role's independently controlled store.

Deployment, HPKE, peer-signing, storage-encryption, wrapping, preprocessing,
ticket, activation, and SigningWorker epochs stay in ceremony/persistence state.
They do not affect the stable KDF scope. This follows the rotation taxonomy at
`docs/router-a-b-sol-refactor.md`, **Root And Key-Continuity Policy**, and the
KDF exclusions in `docs/yaos-ab.md`, **Stable Key Context and Ceremony
Context**.

The existing `RootShareEpoch(String)` at
`crates/router-ab-core/src/derivation/context.rs:72-97` does not express this
separation and is not the Yao provenance epoch type.

## 10. Proof-system-independent verification relations

A verifier accepts a role statement only when later reviewed evidence establishes
all applicable relations.

### 10.1 Stable-context relation

1. Decode exactly two distinct, nonzero participant identifiers, require
   `participant_low < participant_high`, and reject reversed encoded order. A raw
   boundary constructor may normalize caller order before encoding.
2. Recompute `StableKeyDerivationContextV1` and its binding digest using the
   frozen domains and byte order.
3. Match the recomputed digest to `stable_context_binding_digest`.
4. Resolve the authenticated `walletId`, `nearEd25519SigningKeyId`,
   `signingRootId`, and positive immutable `keyCreationSignerSlot`; recompute the
   exact LP32 application-binding encoding and SHA-256 digest; match
   `application_binding_digest`.
5. Confirm that no ceremony or mutable epoch field entered the stable digest or
   KDF info.

### 10.2 Server-input provenance relation

For role `R`:

1. Resolve the authenticated role-root record for the statement's stable scope
   and `role_root_epoch` inside role `R`'s store.
2. Verify the root-binding artifact against that record and private root witness.
3. Evaluate the frozen HKDF-SHA256 contribution KDF with role `R`, source
   `server`, output tags `y` and `tau`, and the stable-context binding to obtain
   the initial role-local server contribution.
4. For the initial state, verify that the role-input-state record equals those KDF
   outputs. For a refreshed state, verify the complete accepted provenance chain
   from the initial KDF outputs through every opposite-signed correlated delta
   and monotonic role-input-state epoch.
5. Verify that the current effective `y_server_R` and canonical
   `tau_server_R` from that state record open the server-input artifact.

### 10.3 Client-envelope and client-input relation

1. Verify the role-specific client-envelope artifact against the authenticated
   envelope plaintext without revealing it to Router or the peer role.
2. Verify that the envelope's wallet/key identity facts, fixed KDF path, role,
   stable context, request, transcript, authorization, and expiry match the
   statement.
3. Verify that its `y_client_R` and canonical `tau_client_R` open the
   client-input artifact.
4. Verify the client-lineage relation selected for production and the paired A/B
   client-envelope-set digest.

The recovery lineage is exact same-root continuity. Its production proof remains
blocked with protected credential/root custody.

### 10.4 Combined circuit-input relation

1. Verify that the combined artifact opens exactly
   `(y_client_R, y_server_R, tau_client_R, tau_server_R)` in the frozen circuit
   input order.
2. Reject every noncanonical `tau` scalar encoding.
3. Bind the tuple to the final circuit digest, input-schema digest, request kind,
   role, transcript, authorization, and current role-input-state record.
4. Verify that the active Yao input wires equal this committed tuple.

### 10.5 Lifecycle relation

- Registration verifies unregistered pre-state, fresh committed inputs, and the
  anti-bias relation in Section 11.
- Recovery verifies exact equality of the logical client root, client KDF
  contributions, role roots, effective contributions, root epochs, input-state
  epochs, joined seed, and public identity without an export branch.
- Refresh verifies the nonzero opposite-delta relation, unchanged role roots and
  root epochs, advancing input-state epochs, and before/after joined-value
  continuity.
- Export verifies explicit export authorization and that reconstructed `d`
  derives the registered public key.

### 10.6 Active-protocol composition relation

The selected active protocol must bind the accepted pair digest to malicious OT,
garbler correctness, evaluator-input consistency, selective-failure resistance,
private randomized outputs, recipient ciphertexts, the transcript root, and a
uniform detectable abort. This document supplies no proof of that composition.

## 11. Registration anti-bias contract

The mandatory registration anti-bias artifact binds at least:

- `registration_intent_digest`;
- stable KDF scope and application binding;
- both role-root record digests and epochs;
- both role-specific client-envelope commitment artifact digests;
- the client-envelope-set digest;
- both role-input-state record digests and initial epochs;
- request/replay identity and transcript digest;
- authorization digest;
- commitment-round transcript or authenticated registry checkpoint;
- retry/attempt lineage and terminal acceptance state.

The reviewed mechanism must establish these invariants:

1. A corrupt Deriver cannot select or grind its root or role input after learning
   an honest client or peer contribution relevant to the accepted key.
2. Router cannot select among multiple valid root records or role-input
   candidates for one wallet/key/stable scope.
3. Both role commitments become fixed before any reveal or challenge used to
   decide acceptance.
4. A retry for one registration intent reuses the same committed logical inputs
   or fails closed; it cannot resample a corrupt role's candidate.
5. At most one public identity is accepted for one registration intent.
6. Replay, crash, timeout, rollback, or peer uncertainty cannot return committed
   candidate state to an available selection pool.
7. The distribution of acceptance and public abort information does not depend
   on the honest role's private input beyond the declared ideal leakage.
8. Evidence binds the exact values subsequently supplied to active Yao.

A preprovisioned signed root-registry checkpoint and a commit-before-reveal
protocol are candidate mechanisms. Phase 1 must select and review one exact
mechanism before registration provenance can be called complete.

Registration input anti-bias is separate from randomized-output-share anti-bias.
The latter requires protocol-generated randomness that neither role can control
(`docs/yaos-ab.md`, **Protocol-Generated Output Sharing**) and remains part of
active-protocol selection.

## 12. Explicit blockers

The application-binding preimage, encoder, validation rules, golden bytes, and
golden digest are closed in the host reference. The following production and
active-security gates remain open.

### 12.1 Ceremony and authorization digest preimages

The semantic ceremony fields are listed, while their canonical encoding remains
open in `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, **Common
public context and leakage**.
Lifecycle-specific authorization scopes and digest encoders also require exact
bytes and golden vectors. Statement vectors cannot claim production transcript
binding before both encoders freeze.

### 12.2 Root records, custody, and epoch persistence

The protected root representation, authenticated role-local lookup API, canonical
root-record bytes, role-input-state record, monotonic counter authority, restore
rules, and atomic update protocol remain unresolved. The numeric outer epoch
encoding and semantic separation in Section 9 do not provide rollback resistance
by themselves.

### 12.3 Commitment and proof artifacts

Phase 6 must select reviewed hiding/binding commitments, proof statements,
verification keys, canonical artifact encodings, and verification algorithms.
`ArtifactDigestV1` cannot replace them. Artifact sizes, setup, proof bytes,
rounds, and proving/verification CPU must be measured.

### 12.4 Registration anti-bias mechanism

Section 11 freezes the acceptance requirements and evidence slot. The exact
preprovisioning or commit-before-reveal protocol, retry state machine, and
selective-abort analysis remain unresolved.

### 12.5 Recovery custody and proof realization

The version-one recovery semantics are frozen as same-logical-client-root rewrap
with unchanged KDF/effective contributions and unchanged root/input-state
epochs. Production still needs the protected boundary that opens and rewraps the
root, proof connecting both credential envelopes to those same root bytes,
role-local current-state commitments, signed receipt bytes, and durable
suspension/promotion/tombstone transactions. See
`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, **Recovery
preservation proof and custody**.

### 12.6 Refresh delta generation, proof, and distributed realization

The opposite-delta algebra and monotonic cutover state machine are frozen.
Production still needs jointly generated nonzero deltas with no Router or client
control, active proof that both next contributions are exact signed-delta
updates, proof of old/new joined-value equality, authenticated package/output
binding, role-local durable transactions, erasure, and crash recovery across
independent deployments. See
`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, **Refresh delta
generation, proof, and distributed cutover**.

### 12.7 Final active circuit and protocol composition

The current `ed25519-yao` crate exposes draft public manifest metadata only
(`crates/ed25519-yao/src/lib.rs:3-7`). Final circuit and input-schema digests,
active input consistency, proof verification, one-use preprocessing, output
authentication, and streaming integration remain later gates.

## 13. Verification evidence matrix

| Requirement                                                                          | Specification evidence                                                                                                                                                                                       | Current implementation evidence                                                                                                                                                 | Alignment                       | Confidence | Required closure                                                                    |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ---------: | ----------------------------------------------------------------------------------- |
| Stable and ceremony contexts are separate                                            | `docs/yaos-ab.md`, **Stable Key Context and Ceremony Context**                                                                                                                                               | Stable-only context at `src/context.rs:107-162`                                                                                                                                 | `partial_match`                 |       0.99 | Add canonical ceremony and statement types without changing stable KDF bytes        |
| Stable context encoding and binding are exact                                        | `docs/yaos-ab.md`, **Stable Key Context and Ceremony Context**                                                                                                                                               | `src/context.rs:5-15,72-162`                                                                                                                                                    | `full_match`                    |       1.00 | Preserve current bytes and golden vector                                            |
| Application binding has an exact immutable preimage                                  | Section 5.1 of this contract                                                                                                                                                                                 | LP32 encoder, boundary types, tests, and committed KDF vector at `src/application_binding.rs`, `tests/application_binding.rs`, and `vectors/ed25519-yao-kdf-v1.json`            | `full_match` for host reference |       1.00 | Preserve the four-field bytes and reproduce them independently                      |
| KDF is role/source/output separated and stable-context bound                         | `docs/yaos-ab.md`, **Stable Key Context and Ceremony Context**                                                                                                                                               | `src/kdf.rs:12-40,182-312`                                                                                                                                                      | `full_match` for host reference |       0.99 | Reproduce inside reviewed production custody/proof boundary                         |
| Activation performs no Yao evaluation                                                | **Fixed Circuit Families** in `docs/yaos-ab.md`; **Product Operation To Ideal Functionality To Circuit Mapping** in `docs/router-a-b-SPEC.md`                                                                | `consume_activation_metadata_v1` move-consumes synthetic metadata and constructs a private zero-reference-work witness; package opening and the production evaluator are absent | `partial_match`                 |       0.99 | Bind and consume authenticated committed packages in the final activation path      |
| Lifecycle-to-circuit mapping is fixed                                                | `docs/yaos-ab.md`, **Fixed Circuit Families**                                                                                                                                                                | Branch-specific wrappers derive request kind, recipient plan, output kind, and activation/export family in `src/lifecycle_domain.rs`; final artifact digests are absent         | `partial_match`                 |       0.99 | Bind the selected final active artifact digests                                     |
| Each role input is tied to root, wallet/key/path, epoch, request, envelope, and auth | `docs/yaos-ab.md`, **Input Provenance**                                                                                                                                                                      | Raw contribution tuples only at `src/lib.rs:137-159,257-340`                                                                                                                    | `missing_in_code`               |       1.00 | Implement statement parser, authenticated records, artifacts, and reviewed verifier |
| Tau inputs reject noncanonical encodings                                             | `docs/yaos-ab.md`, **Field and Byte Conventions**                                                                                                                                                            | Role-specific parsing and construction at `src/lib.rs:181-254,265-317`                                                                                                          | `full_match` for host reference |       1.00 | Apply the same rule before proof/circuit input acceptance                           |
| Root epoch and input-state epoch have distinct semantics                             | **Root And Key-Continuity Policy** in `docs/router-a-b-sol-refactor.md`; **Stable Key Context and Ceremony Context** in `docs/yaos-ab.md`                                                                    | Host-semantic root-share, A/B input-state, and activation epoch types are distinct and validate nonzero/advancing transitions; authoritative production stores are absent       | `partial_match`                 |       0.98 | Add role-typed production epochs and authoritative store checks                     |
| Registration input selection is unbiased against one corrupt role                    | `docs/yaos-ab.md`, **Input Provenance**                                                                                                                                                                      | No anti-bias state or evidence type                                                                                                                                             | `missing_in_code`               |       1.00 | Select mechanism, prove retry/abort properties, and add adversarial vectors         |
| Recovery preserves seed/public identity without export                               | **Fixed Circuit Families** in `docs/yaos-ab.md`; **F_ed25519_recovery_v1** and **Recovery preservation proof and custody** in `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`                 | Committed same-root recovery/activation cases pass Rust relation tests and independent Python reproduction; production custody, proof, and cutover are absent                   | `partial_match`                 |       1.00 | Implement protected rewrap, same-root proof, receipts, and durable transactions     |
| Refresh preserves joined values across epoch cutover                                 | **Fixed Circuit Families** in `docs/yaos-ab.md`; **F_ed25519_refresh_v1** and **Refresh delta generation, proof, and distributed cutover** in `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md` | Committed opposite-delta refresh/activation cases pass Rust and independent Python checks; production delta generation, proof, and distributed cutover are absent               | `partial_match`                 |       1.00 | Implement joint delta generation, active transition proof, and distributed cutover  |
| Commitments are hiding, binding, and proof-composed                                  | **Input Provenance** and **Online Ceremony** in `docs/yaos-ab.md`                                                                                                                                            | No commitment/proof types in `ed25519-yao`; crate boundary at `crates/ed25519-yao/src/lib.rs:3-7`                                                                               | `missing_in_code`               |       1.00 | Select and independently review Phase 6 suite; measure its costs                    |
| A/B statements are role-bound and cannot be swapped                                  | **Goal** and **Network and Administrative Edges** in `docs/yaos-ab.md`                                                                                                                                       | KDF role tags exist at `src/kdf.rs:20-30`; no statement pair                                                                                                                    | `partial_match`                 |       0.98 | Add sealed A/B types, pair verifier, swap/replay/cross-wallet tests                 |

## 14. Required vectors and negative tests

Before any blocker is marked complete, add independently reproduced vectors for:

- every nested encoding, statement encoding, statement digest, envelope-set
  digest, pair encoding, pair digest, and artifact-wrapper digest;
- A and B statements for registration, recovery, refresh, and export;
- participant ordering and stable-context binding continuity;
- different role-root and role-input-state epochs for A and B;
- recovery current snapshots plus exact same-root, same-contribution, and
  same-root/input-state-epoch continuity;
- refresh before/after snapshots with nonzero opposite deltas and advancing
  input-state epochs;
- the exact four-field application binding and transcript, request-context, and
  authorization digest preimages.

Boundary and compile-fail tests must reject:

- activation as an evaluation statement;
- an activation/export family mismatch;
- an incorrect circuit identifier, circuit digest, or input-schema digest;
- A/B role swaps, duplicate roles, and wrong envelope ordering;
- stable-scope bytes containing mutable epochs or ceremony metadata;
- application bindings with missing or reordered fields, `nearAccountId`, zero
  `keyCreationSignerSlot`, `signingRootVersion`, or any mutable epoch;
- unknown fields, missing required digests, trailing bytes, and alternate order;
- an arbitrary digest accepted without recomputation or authenticated lookup;
- stale, zero, repeated, regressing, or ambiguous epochs;
- cross-wallet, cross-key, cross-path, cross-request, cross-authorization,
  cross-transcript, and cross-circuit artifact reuse;
- noncanonical `tau` values and invalid registered Ed25519 points;
- recovery mapped to export or carrying seed-output fields;
- recovery that replaces the logical client root, changes any KDF/effective
  contribution, or advances a root/input-state epoch;
- refresh with zero, noncanonical, same-sign, or mismatched-domain deltas;
- refresh evidence that changes joined `y`, joined `tau`, `d`, or `A_pub`, keeps
  an input-state epoch unchanged, changes a root epoch, or rolls back after
  `OutputCommitted`;
- registration retry that selects a different role root or role input;
- direct hashes of a private root or secret role-input tuple used as an artifact.

## 15. Readiness verdict

The canonical outer contract and four-field application binding are detailed
enough to scaffold strict host-only types, encoders, decoders, and synthetic
vectors. Same-root recovery semantics and opposite-delta refresh/cutover
semantics are frozen. None of these artifacts is production provenance evidence.

Phase 1 provenance remains open until ceremony and authorization preimages,
production root/state records, registration anti-bias, protected recovery
custody/proof, refresh delta generation and distributed realization, and the
commitment/proof artifact relations are complete. Phase 6 must then select and
review the active-protocol composition before any security claim is enabled.

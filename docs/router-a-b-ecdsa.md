# Router A/B ECDSA-HSS Plan

Date created: June 13, 2026

Related docs:

- [Router A/B Deriver Architecture Plan](router-A-B-signer.md)
- [Router A/B Deriver Spec](router-A-B-signer-SPEC.md)
- [ECDSA-HSS protocol](../crates/ecdsa-hss/specs/protocol.md)
- [ECDSA-HSS export](../crates/ecdsa-hss/specs/export.md)
- [ECDSA-HSS true server-blindness](../crates/ecdsa-hss/docs/plans/true-server-blindness.md)

## Summary

ECDSA-HSS maps cleanly to the Router-A-B-SigningWorker architecture as a
post-MVP protocol version.

The Router-A-B topology is useful for ECDSA-HSS registration, session
bootstrap, recovery, explicit key export, and SigningWorker activation. It
keeps server-side provisioning material split across Deriver A and Deriver B so
no single provisioning worker sees enough material to reconstruct or export the
logical secp256k1 private key.

Normal ECDSA signing remains on the hot path:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

Deriver A and Deriver B do not participate in each normal ECDSA signature.

## Security Rationale

The current ECDSA-HSS role-local design is:

```text
x = x_client + x_relayer mod n
X_client = x_client * G
X_relayer = x_relayer * G
X = X_client + X_relayer
address = ethereum_address(X)
```

The active ECDSA-HSS server-blindness invariant is that production server paths
must not reconstruct canonical `x`, must not return `privateKeyHex`, and must
not accept both `y_client` and `y_relayer` in one process.

Router-A-B strengthens that boundary operationally:

- Router owns public auth, policy, replay, lifecycle, and routing.
- Deriver A owns only A-side ECDSA-HSS provisioning material.
- Deriver B owns only B-side ECDSA-HSS provisioning material.
- SigningWorker receives only activated ECDSA signing material for normal
  signing.
- The authorized client export runtime is the only place allowed to reconstruct
  canonical `x`.

A single compromised Deriver cannot reconstruct `x_relayer`, canonical `x`, or
`privateKeyHex`. A single compromised Router sees only public metadata and
ciphertext. A single compromised SigningWorker may expose active signing-worker
material, but should not expose Deriver A/B root material or client export
material.

## Target Protocol Version

Add a separate protocol version:

```text
router_ab_ecdsa_hss_secp256k1_v1
```

This version must have ECDSA-specific:

- domain labels
- transcript fields
- envelope kinds
- output kinds
- proof-bundle commitments
- activation records
- export authorization records
- fixture and vector files
- source guards

Do not reuse the Ed25519-HSS Router-A-B protocol version for ECDSA-HSS.

Terminology: existing ECDSA-HSS specs use `relayer` for the server-side ECDSA
share role and variables such as `y_relayer` and `x_relayer`. This plan uses
`SigningWorker` for the Router-A-B runtime role and keeps the existing
`*_relayer` variable names until the ECDSA-specific version freezes a rename.

## Role Mapping

| Role | Responsibility |
| --- | --- |
| Client | Derives and stores client-side ECDSA-HSS material, owns `x_client`, verifies public identity, reconstructs `x` only during explicit export |
| Router | Public API, auth, policy, quota, replay, lifecycle, opaque routing, response aggregation |
| Deriver A | A-side server provisioning share, A-side proof bundles, A-side export contribution |
| Deriver B | B-side server provisioning share, B-side proof bundles, B-side export contribution |
| SigningWorker | Opens activated SigningWorker-recipient ECDSA material and performs normal ECDSA signing |

## Flows

### Registration / Bootstrap

```text
Client -> Router: public ECDSA-HSS context, X_client, encrypted A/B envelopes
Router -> Deriver A: A envelope, public request metadata
Router -> Deriver B: B envelope, public request metadata
Deriver A <-> Deriver B: authenticated derivation protocol
Deriver A -> SigningWorker: encrypted SigningWorker activation bundle A
Deriver B -> SigningWorker: encrypted SigningWorker activation bundle B
SigningWorker -> Router: activation receipt with public ECDSA identity
Router -> Client: public identity, activation receipt, client-facing evidence
```

The SigningWorker opens only the material intended for it. It derives or
receives enough public evidence to return:

- `X_relayer`
- `X = X_client + X_relayer`
- Ethereum address
- activation digest
- SigningWorker identity and key epoch

Router can validate public receipt shape, but it cannot decrypt A/B envelopes or
SigningWorker activation bundles.

### Explicit Key Export

```text
Client -> Router: export request, confirmation evidence, export nonce
Router -> Deriver A: A export envelope
Router -> Deriver B: B export envelope
Deriver A <-> Deriver B: authenticated export derivation protocol
Deriver A -> Router: encrypted client export bundle A
Deriver B -> Router: encrypted client export bundle B
Router -> Client: export bundles, metadata, and delivery status
Client: opens export bundles, reconstructs x, verifies xG == X
```

The key export path should require Deriver A/B participation. The SigningWorker
should not release active signing material for export. Export must remain:

- explicit
- user-confirmed
- transcript-bound
- nonce/replay protected
- auditable
- client-side reconstructed and verified

The server-side export response must never contain:

- canonical `x`
- `privateKeyHex`
- `x_client`
- `y_client`
- `y_relayer`
- backend threshold private shares

### Normal ECDSA Signing

```text
Client -> Router
Router -> SigningWorker
SigningWorker -> Router
Router -> Client
```

Normal signing uses the activated SigningWorker state. Router-A-B adds no A/B
round trip to each normal ECDSA signature.

If the current ECDSA signing backend still needs a threshold client-side
participant for a specific signing mode, that protocol remains a
SigningWorker/client signing protocol. Deriver A/B stay out of online signing.

## Material Boundaries

| Material | Allowed location |
| --- | --- |
| `y_client` | Client only |
| `x_client` | Client only |
| Deriver A root/provisioning share | Deriver A only |
| Deriver B root/provisioning share | Deriver B only |
| Joined `y_relayer` | No single production worker |
| Joined `x_relayer` before activation | No Deriver or Router plaintext |
| Activated SigningWorker material | SigningWorker only |
| Canonical `x` / `privateKeyHex` | Authorized client export runtime only |
| ECDSA presign/triple/nonce material | SigningWorker/signing backend only |
| Public `X_client`, `X_relayer`, `X`, address | Public transcript, after validation |

## Implementation Plan

### Phase 0: Scope Freeze

- [ ] Keep this work post-MVP until the current Router-A-B Ed25519-HSS path is
      stable.
- [ ] Freeze the protocol version name:
      `router_ab_ecdsa_hss_secp256k1_v1`.
- [ ] Decide whether this version creates new ECDSA-HSS keys only or must
      preserve existing role-local `threshold_ecdsa_hss_role_local_v2` keys.
- [ ] Keep normal signing outside A/B.
- [ ] Treat threshold/MPC ECDSA online signing changes as a separate protocol.

### Phase 1: ECDSA-Specific Spec

- [ ] Add ECDSA-HSS Router-A-B protocol spec with role definitions, state
      machine, transcript fields, envelope kinds, output kinds, and rejection
      rules.
- [ ] Define ECDSA-specific domains for:
      context binding, Deriver A/B derivation, SigningWorker activation, export
      authorization, public identity, and proof-bundle commitments.
- [ ] Bind these fields in every registration/export transcript:
      wallet id, RP id, key scope, ECDSA threshold key id, signing root id,
      signing root version, key purpose, key version, Deriver A identity,
      Deriver B identity, SigningWorker identity, client identity, replay nonce,
      and request kind.
- [ ] Define how `X_client`, `X_relayer`, `X`, and Ethereum address are produced,
      verified, and persisted.
- [ ] Define activation receipt contents and failure cases.

### Phase 2: Core Types And Wire Shapes

- [ ] Add protocol ids, request kinds, output kinds, and wire-message variants
      for ECDSA-HSS Router-A-B.
- [ ] Add typed ECDSA transcript metadata separate from Ed25519-HSS transcript
      metadata.
- [ ] Add ECDSA Deriver A/B encrypted envelope plaintext types.
- [ ] Add ECDSA SigningWorker activation payload and receipt types.
- [ ] Add ECDSA export authorization and export-delivery payload types.
- [ ] Add boundary parsers that reject raw route bodies before core logic.

### Phase 3: A/B ECDSA Derivation Backend

- [ ] Choose the ECDSA-HSS A/B derivation primitive.
- [ ] Prefer adapting the selected Router-A-B threshold-PRF backend to produce
      secp256k1 scalar material under ECDSA-specific domain labels.
- [ ] Define non-zero scalar reduction and retry semantics.
- [ ] Produce recipient-scoped proof bundles for:
      `x_relayer -> SigningWorker` and `x_relayer_export -> client`.
- [ ] Produce public commitments sufficient to verify `X_relayer`,
      `X = X_client + X_relayer`, and Ethereum address parity.
- [ ] Add deterministic vectors for scalar validity, zero-sum retry, public key
      parity, address parity, transcript mismatch, wrong recipient, and wrong
      SigningWorker identity.

### Phase 4: Registration And Activation

- [ ] Add Router public request boundary for ECDSA-HSS registration/bootstrap.
- [ ] Add Deriver A/B private handlers for ECDSA registration/bootstrap.
- [ ] Add direct A/B peer authentication and transcript binding for ECDSA-HSS.
- [ ] Add direct Deriver A/B -> SigningWorker activation delivery for
      latency-sensitive deployments.
- [ ] Add Router-mediated activation relay as an optional restricted deployment
      profile using the same ciphertext.
- [ ] Add SigningWorker activation handler that opens only ECDSA-HSS
      SigningWorker-targeted material and returns a public receipt.
- [ ] Persist active ECDSA SigningWorker state by account, ECDSA threshold key
      id, signing root id/version, SigningWorker identity, and activation epoch.

### Phase 5: Explicit Export

- [ ] Add Router export boundary with user-confirmation evidence, export nonce,
      expiry, and export authorization digest.
- [ ] Add Deriver A/B export handlers that produce only client-recipient export
      bundles.
- [ ] Ensure the SigningWorker does not release active ECDSA material for export.
- [ ] Add client export reconstruction and verification rules:
      `x_export * G == X` and `ethereum_address(X) == expected_address`.
- [ ] Add nonce replay protection and failure-burning behavior.
- [ ] Add audit events that include operation kind, public key/address
      fingerprint, authorization digest, nonce fingerprint, and result.
- [ ] Source-guard logs and telemetry against `x`, `x_client`, `x_relayer`,
      `privateKeyHex`, raw root material, and presign scalar material.

### Phase 6: Normal Signing Integration

- [ ] Add Router-to-SigningWorker normal ECDSA signing request shape if the
      existing one cannot carry the new activation identity.
- [ ] Bind normal signing requests to active ECDSA SigningWorker state.
- [ ] Keep A/B derivation handlers unreachable from normal signing routes.
- [ ] Add source guards proving normal signing routes cannot call ECDSA-HSS
      registration, export, recovery, or activation handlers.
- [ ] Preserve existing ECDSA signing latency expectations.

### Phase 7: Recovery And Refresh

- [ ] Define ECDSA-HSS recovery semantics under Router-A-B.
- [ ] Define SigningWorker activation refresh after Deriver A/B root-share
      rotation.
- [ ] Verify public identity parity before and after refresh.
- [ ] Invalidate stale SigningWorker activation state after rotation.
- [ ] Add rollback rejection for old activation epochs.

### Phase 8: Validation And Benchmarks

- [ ] Add native core tests for all ECDSA-HSS Router-A-B boundary parsers.
- [ ] Add vectors for registration, activation, export, recovery, wrong
      recipient, wrong Deriver identity, wrong SigningWorker identity, replay,
      expiry, and public-key/address mismatch.
- [ ] Add source guards proving no production Router, Deriver, SigningWorker,
      log, audit, or persistence path materializes canonical `x`.
- [ ] Add Wasm adapter tests for Cloudflare boundary parsing.
- [ ] Benchmark registration/bootstrap latency.
- [ ] Benchmark explicit export latency.
- [ ] Benchmark normal ECDSA signing latency and verify A/B adds no normal
      signing round trip.

## Open Decisions

- Should `router_ab_ecdsa_hss_secp256k1_v1` preserve existing role-local ECDSA
  key identity or require fresh ECDSA keys?
- Should ECDSA-HSS export always rederive export material from Deriver A/B, or
  can a hardened deployment allow SigningWorker export under stronger policy?
- Which public proof is enough to bind `X_relayer` to A/B output without
  leaking `x_relayer` to Router or a Deriver?
- Do Deriver A and Deriver B live in separate Cloudflare accounts for ECDSA-HSS
  production?
- Does ECDSA-HSS need direct A/B -> SigningWorker activation in v1, or is
  Router-mediated activation acceptable for the first ECDSA release?
- Which ECDSA signing modes still require client participation after
  SigningWorker activation?

## Non-Goals

- Rewriting Cait-Sith, triples, presign, or threshold ECDSA signing.
- Adding Deriver A/B to every normal ECDSA signature.
- Returning `privateKeyHex` from any server, Router, Deriver, or SigningWorker
  path.
- Compatibility with old joined ECDSA-HSS server paths.
- Sharing Ed25519-HSS protocol ids, vectors, or transcript labels with
  ECDSA-HSS.

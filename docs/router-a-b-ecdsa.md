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
pre-deploy protocol version for the Cloudflare Router A/B release.

This document owns the release-blocking ECDSA-HSS Router-A-B plan. The
Ed25519-HSS Wallet Session V2 normal-signing cutover remains necessary, and the
Cloudflare Router A/B deployment is blocked until ECDSA-HSS registration,
activation, normal signing integration, export, recovery/refresh semantics, and
validation are implemented or explicitly removed from the release scope.

No staging or production Cloudflare Router A/B deploy should proceed until this
plan's release acceptance criteria pass.

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
x = x_client + x_server mod n
X_client = x_client * G
X_server = x_server * G
X = X_client + X_server
address = ethereum_address(X)
```

The active ECDSA-HSS server-blindness invariant is that production server paths
must not reconstruct canonical `x`, must not return `privateKeyHex`, and must
not accept both `y_client` and `y_server` in one process.

Router-A-B strengthens that boundary operationally:

- Router owns public auth, policy, replay, lifecycle, and routing.
- Deriver A owns only A-side ECDSA-HSS provisioning material.
- Deriver B owns only B-side ECDSA-HSS provisioning material.
- SigningWorker receives only activated ECDSA signing material for normal
  signing.
- The authorized client export runtime is the only place allowed to reconstruct
  canonical `x`.

A single compromised Deriver cannot reconstruct `x_server`, canonical `x`, or
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

The version must bind secp256k1 compressed public keys, Ethereum address,
context binding, Deriver A identity, Deriver B identity, SigningWorker identity,
export authorization digest, and replay nonce into ECDSA-specific transcripts.

Terminology: existing ECDSA-HSS specs use `server` for the server-side ECDSA
share role and variables such as `y_server` and `x_server`. This plan uses
`SigningWorker` for the Router-A-B runtime role and keeps the existing
`*_server` variable names until the ECDSA-specific version freezes a rename.

## Role Mapping

| Role | Responsibility |
| --- | --- |
| Client | Derives and stores client-side ECDSA-HSS material, owns `x_client`, verifies public identity, reconstructs `x` only during explicit export |
| Router | Public API, auth, policy, quota, replay, lifecycle, opaque routing, response aggregation |
| Deriver A | A-side server provisioning share, A-side proof bundles, A-side export contribution |
| Deriver B | B-side server provisioning share, B-side proof bundles, B-side export contribution |
| SigningWorker | Opens activated SigningWorker-recipient ECDSA material and performs normal ECDSA signing |

## Protocol Spec

`router_ab_ecdsa_hss_secp256k1_v1` is a Router-A/B protocol that derives or
refreshes ECDSA-HSS server-side material outside the normal-signing hot path.
The public Router boundary accepts typed registration/bootstrap, explicit
export, recovery, activation-refresh, prepare, and finalize requests. The
private Deriver boundary accepts only Router-forwarded, role-encrypted A/B
envelopes. The private SigningWorker boundary accepts only activated
SigningWorker-recipient material, pool-fill records from a trusted producer,
and Router-admitted prepare/finalize requests.

State machine:

```text
registration/refresh:
requested -> admitted -> A envelope forwarded -> B envelope forwarded
  -> A/B running -> SigningWorker output ready -> activated

export/recovery:
requested -> admitted -> A envelope forwarded -> B envelope forwarded
  -> A/B running -> client output ready

normal signing:
Router prepare admission -> replay reserve -> SigningWorker pool reserve
  -> request-bound one-use presignature record -> finalize take -> response
```

Any state can terminate as failed, expired, or abandoned before activation or
client output. Activated state replacement requires a newer activation
timestamp for the same account, active-state session id, and SigningWorker.

ECDSA-HSS transcript domains are protocol-specific:

| Domain | Current label |
| --- | --- |
| Stable key context | `ecdsa-hss:context:v2` |
| Context binding | `ecdsa-hss:role-local:v2:context-binding` |
| Public identity | `router-ab-protocol/ecdsa-hss/public-identity/v1` |
| Registration request | `router-ab-protocol/ecdsa-hss/registration-request/v1` |
| Export request | `router-ab-protocol/ecdsa-hss/export-request/v1` |
| Recovery request | `router-ab-protocol/ecdsa-hss/recovery-request/v1` |
| Activation refresh request | `router-ab-protocol/ecdsa-hss/refresh-request/v1` |
| Normal-signing scope | `router-ab-protocol/ecdsa-hss/normal-signing-scope/v1` |
| Prepare request | `router-ab-protocol/ecdsa-hss/normal-signing-request/v1` |
| Finalize request | `router-ab-protocol/ecdsa-hss/normal-signing-finalize-request/v1` |

Every registration, export, recovery, and refresh transcript binds wallet id,
RP id, key scope, ECDSA threshold key id, signing root id, signing root version,
key purpose, key version, Router id, Deriver A identity, Deriver B identity,
SigningWorker identity, client identity, replay nonce, request kind,
secp256k1 compressed public keys where applicable, Ethereum address where
applicable, and the context binding. Export binds the export authorization
digest. Recovery binds the recovery authorization digest. Refresh binds the
refresh authorization digest plus previous and next activation epochs. Normal
signing binds the active normal-signing scope digest, request id, selected
client presignature id, signing digest, expiry, prepare digest, and finalize
client signature share.

The active-state session id is:

```text
{ecdsa_threshold_key_id}:{signing_root_id}:{signing_root_version}:{activation_epoch}
```

That value is the Wallet Session `session_id` for ECDSA-HSS normal signing and
the SigningWorker active-state lookup key component. This prevents one wallet,
key id, and worker from colliding across signing root versions or activation
epochs.

Envelope and output kinds:

| Operation | Deriver envelopes | Output |
| --- | --- | --- |
| Registration/bootstrap | Signer A/B registration envelopes | SigningWorker activation bundles |
| Explicit export | Signer A/B export envelopes | Client-recipient export bundles |
| Recovery | Signer A/B recovery envelopes | Client-recipient recovery/export bundles |
| Activation refresh | Signer A/B refresh envelopes | SigningWorker activation bundles for the next epoch |
| Normal signing | None | SigningWorker ECDSA signature response |

Public identity equations:

```text
X_client = x_client * G
X_server = x_server * G
X = X_client + X_server
ethereum_address = last20(keccak256(uncompressed(X)[1..]))
```

The client verifies explicit export by reconstructing `x_export`, checking
`x_export * G == X`, and checking the Ethereum address derived from `X`.
SigningWorker activation verifies the opened server material by deriving the
public server key and requiring the resulting public identity to equal the
activated identity. Refresh must preserve public identity while advancing the
activation epoch.

Activation receipts contain the stable ECDSA-HSS context, public identity,
SigningWorker identity, activation epoch, activation digest, activated timestamp,
and generic SigningWorker output storage receipt. Failure cases include
malformed or unknown fields, wrong envelope role, wrong Deriver identity, wrong
SigningWorker identity, stale or non-advancing activation epoch, expired
request, replayed nonce, authorization digest mismatch, context/public-identity
mismatch, active-state mismatch, public key/address mismatch, and presignature
record drift or replay.

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

- `X_server`
- `X = X_client + X_server`
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
- `y_server`
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
| Joined `y_server` | No single production worker |
| Joined `x_server` before activation | No Deriver or Router plaintext |
| Activated SigningWorker material | SigningWorker only |
| Canonical `x` / `privateKeyHex` | Authorized client export runtime only |
| ECDSA presign/triple/nonce material | SigningWorker/signing backend only |
| Public `X_client`, `X_server`, `X`, address | Public transcript, after validation |

## Implementation Plan

Current status as of 2026-06-16:

- [x] Existing passkey ECDSA transaction signing works in the local browser stack
      started with `pnpm build:sdk && pnpm router`.
- [x] Normal ECDSA signing remains off the A/B derivation path in the validated
      local stack.
- [x] Router A/B ECDSA-HSS registration, activation, export, recovery, refresh,
      and normal signing are implemented locally and are required before any
      Cloudflare Router A/B staging or production deploy. Deployed evidence and
      real deploy inputs remain tracked below.
- [x] Initial `router_ab_ecdsa_hss_secp256k1_v1` core request/identity types,
      strict JSON parsers, strict Cloudflare public registration/export routes,
      and Router-mediated ECDSA-HSS SigningWorker activation are implemented
      locally.
- [x] ECDSA-HSS explicit export now routes Deriver A/B through client-only
      private export handlers and response types, so export does not produce
      unused SigningWorker-targeted bundles.
- [x] ECDSA-HSS recovery now routes Deriver A/B through client-only private
      recovery handlers from the strict public Router recovery route.
- [x] ECDSA-HSS activation refresh now routes through a typed public Router
      refresh endpoint, Deriver A/B refresh handlers, and a distinct
      SigningWorker refresh activation route that preserves public identity.
- [x] SigningWorker ECDSA-HSS presignature state now has typed one-use
      Cloudflare Durable Object put/take/cleanup semantics bound to the active
      SigningWorker state, canonical request digest, and admitted signing
      digest.
- [x] ECDSA-HSS normal signing now has an explicit finalize request boundary
      carrying the server presignature id and 32-byte client signature share,
      bound back to the matching prepare request digest.
- [x] ECDSA-HSS normal-signing prepare now has a public response boundary and a
      SigningWorker private prepare fetch helper that persists one-use
      presignature state before returning the redacted public response.
- [x] Router public ECDSA-HSS prepare admission now verifies Wallet Session,
      derives Router-owned normal-signing policy/quota/abuse admission, reserves
      replay, and forwards only a Router-admitted request to SigningWorker.
- [x] ECDSA-HSS prepare responses and one-use SigningWorker presignature state
      now carry required 32-byte rerandomization entropy, bind that entropy
      across response, Durable Object record, and put receipt, and keep scalar
      shares redacted from the public response.
- [x] Strict public Router routes now dispatch ECDSA-HSS prepare and finalize
      requests through the Wallet Session authenticated boundary.
- [x] Strict private SigningWorker finalize now dispatches to the production
      `signer-core` finalize handler and returns a real recoverable secp256k1
      signature bound to the exact prepare request.
- [x] ECDSA-HSS prepare requests now require `client_presignature_id`, bind it
      into the canonical prepare digest, expose it in Router prepare admission,
      and require prepare responses to echo it as the server presignature id.
- [x] ECDSA-HSS registration now uses protocol-specific Deriver A/B private
      registration requests and strict private Deriver routes before
      SigningWorker activation.
- [x] Strict private SigningWorker ECDSA-HSS prepare now reserves a
      client-selected unbound presignature pool record, binds it to the exact
      prepare request, writes the existing one-use request-bound presignature
      record, and returns only the redacted public prepare response.
- [x] Strict private SigningWorker ECDSA-HSS pool-fill now accepts validated
      presignature shares from a trusted presign producer, derives active state
      from the ECDSA-HSS scope, and writes the unbound pool record without
      accepting caller-supplied active state.
- [x] Active ECDSA-HSS SigningWorker state is now keyed by wallet id, ECDSA
      threshold key id, signing root id/version, SigningWorker identity, and
      activation epoch through the canonical active-state session id.
- [x] SDK/server now has a typed Router A/B ECDSA-HSS presignature bridge that
      maps the existing public TypeScript threshold-ECDSA presign output plus
      validated ECDSA-HSS scope into the strict private SigningWorker
      pool-fill request. The new Router A/B boundary uses `serverKeyId`
      terminology and keeps legacy `relayerKeyId` conversion isolated at the
      existing threshold-ECDSA store adapter.
- [x] SDK/server now has a producer-side sender for the strict private
      SigningWorker pool-fill route with exact-path POST, receipt parsing,
      internal service-auth header propagation, request/receipt drift
      rejection, and explicit duplicate handling.
- [x] SDK/server threshold-ECDSA presign sessions now carry an explicit
      pool-fill destination branch, validate Router A/B ECDSA-HSS scope against
      Wallet Session claims and role-local ECDSA material at init, and invoke
      the strict private SigningWorker pool-fill sender when presign completes.
- [x] ECDSA-HSS Deriver A/B encrypted envelope plaintext now has
      branch-specific registration/export/recovery/refresh types with canonical
      plaintext digests, envelope role/AAD binding, exact output-kind
      validation, exact work-kind validation, and source guards against private
      scalar/root material.
- [x] ECDSA-HSS deterministic derivation vectors now execute the committed
      role-local fixture for scalar validity, public-key sum, Ethereum address
      parity, retry counters, and client-side export reconstruction, with
      negative coverage for zero-sum identity, transcript operation drift,
      wrong Deriver recipient, and wrong SigningWorker identity.
- [x] Signer A/B runtimes now carry explicit SigningWorker service bindings for
      direct activation delivery, with wrangler config, release-ready guards, and
      Worker env validation covering base, staging, and production environments.
- [x] Direct Deriver-to-SigningWorker activation delivery now has a narrow
      single-bundle request type that carries only activation context, Deriver
      role, and one SigningWorker-recipient `x_server_base` proof bundle.
- [x] Direct activation deliveries now have deterministic in-memory
      reconciliation: exactly one Signer A delivery and one Signer B delivery
      for the same activation context produce the existing aggregate
      SigningWorker activation request; duplicate roles or context drift fail
      deterministically.
- [x] Source guards now pin direct activation delivery to
      SigningWorker-recipient `x_server_base` bundles and reject accidental
      client/export bundle surface at the direct-delivery boundary.
- [x] Direct Deriver-to-SigningWorker activation delivery is wired through strict
      registration and refresh Deriver routes. Each Deriver posts a single
      server-recipient delivery to the private SigningWorker ECDSA-HSS activation
      route after private validation succeeds. The SigningWorker route accepts
      either full Router-mediated activation or a direct single-Deriver delivery;
      the SigningWorker Durable Object stores the first delivery, returns
      pending, merges the peer delivery into an aggregate, and activates the
      generic SigningWorker output state exactly once with idempotent repeat
      handling and deterministic conflict rejection.
      Validation: `rtk cargo test --manifest-path
      crates/router-ab-cloudflare/Cargo.toml --test bindings --test
      source_guards`, plus `rtk cargo check --manifest-path
      crates/router-ab-cloudflare/Cargo.toml --features
      strict-worker-signer-a-entrypoint`, `strict-worker-signer-b-entrypoint`,
      `strict-worker-signing-worker-entrypoint`, and
      `strict-worker-router-entrypoint`.
- [ ] Release remains blocked on deployed Cloudflare runtime evidence,
      deploy/runtime validation, and remaining real deploy inputs such as Router
      JWT configuration, Cloudflare credentials, and Deriver A/B root-share wire
      secrets.

Treat the local ECDSA transaction result as hot-path signing evidence. It does
not complete the Cloudflare Router A/B ECDSA-HSS release requirement or
`router_ab_ecdsa_hss_secp256k1_v1`.

### Phase 0: Release Scope Freeze

- [x] Classify ECDSA-HSS Router-A-B support as a pre-deploy release blocker for
      Cloudflare Router A/B.
- [x] Block staging and production Cloudflare Router A/B deploys until the
      ECDSA-HSS release acceptance criteria pass.
- [x] Freeze the protocol version name:
      `router_ab_ecdsa_hss_secp256k1_v1`.
- [x] Decide that this version creates Router-A-B ECDSA-HSS activation/export
      material without preserving legacy role-local
      `threshold_ecdsa_hss_role_local_v2` keys.
- [x] Keep normal signing outside A/B.
- [x] Treat threshold/MPC ECDSA online signing changes as a separate protocol.

### Phase 1: ECDSA-Specific Spec

- [x] Add ECDSA-HSS Router-A-B protocol spec with role definitions, state
      machine, transcript fields, envelope kinds, output kinds, and rejection
      rules.
- [x] Define ECDSA-specific domains for:
      context binding, Deriver A/B derivation, SigningWorker activation, export
      authorization, public identity, and proof-bundle commitments.
- [x] Bind these fields in every registration/export transcript:
      wallet id, RP id, key scope, ECDSA threshold key id, signing root id,
      signing root version, key purpose, key version, Deriver A identity,
      Deriver B identity, SigningWorker identity, client identity, replay nonce,
      export authorization digest, secp256k1 compressed public keys, Ethereum
      address, context binding, and request kind.
- [x] Define how `X_client`, `X_server`, `X`, and Ethereum address are produced,
      verified, and persisted.
- [x] Define activation receipt contents and failure cases.

### Phase 2: Core Types And Wire Shapes

- [x] Add protocol ids, request kinds, output kinds, and typed public request
      shapes for ECDSA-HSS Router-A-B.
- [x] Add typed ECDSA stable-key context and transcript binding separate from
      Ed25519-HSS normal-signing metadata.
- [x] Add ECDSA Deriver A/B encrypted envelope plaintext types.
- [x] Add ECDSA SigningWorker activation payload and receipt types.
- [x] Add ECDSA export authorization and export-delivery response boundary
      types.
- [x] Add typed ECDSA-HSS EVM digest signing request boundary with request id,
      expiry, active normal-signing scope, and exact 32-byte signing digest.
- [x] Add typed ECDSA-HSS EVM digest prepare response boundary with
      server-presignature id, server public presignature point, exact request
      digest, signing digest, rerandomization entropy, and redacted scalar-share
      surface.
- [x] Add typed ECDSA-HSS recoverable signature response boundary and bind it to
      the exact request digest and signing digest.
- [x] Add boundary parsers that reject raw route bodies before core logic.

### Phase 3: A/B ECDSA Derivation Backend

- [x] Choose the ECDSA-HSS A/B derivation primitive.
- [x] Prefer adapting the selected Router-A-B threshold-PRF backend to produce
      secp256k1 scalar material under ECDSA-specific domain labels.
- [x] Define non-zero scalar reduction and retry semantics through the existing
      ECDSA-HSS role-local derivation API.
- [x] Produce recipient-scoped proof bundles for:
      `x_server -> SigningWorker` and `x_server_export -> client`.
- [x] Produce public commitments sufficient to verify `X_server`,
      `X = X_client + X_server`, and Ethereum address parity.
- [x] Add deterministic vectors for scalar validity, zero-sum retry, public key
      parity, address parity, transcript mismatch, wrong recipient, and wrong
      SigningWorker identity.

### Phase 4: Registration And Activation

- [x] Add Router public request boundary for ECDSA-HSS registration/bootstrap.
- [x] Add Deriver A/B private handlers for ECDSA registration/bootstrap.
- [x] Add direct A/B peer authentication and transcript binding for ECDSA-HSS
      through the existing Router A/B proof-bundle transport.
- [x] Add direct Deriver A/B -> SigningWorker activation delivery for
      latency-sensitive deployments.
      - [x] Add explicit Signer A and Signer B service bindings for the
            SigningWorker activation endpoint.
      - [x] Add a narrow direct-delivery request type that carries only the
            validated activation context, Deriver role, and that Deriver's
            SigningWorker-recipient bundle.
      - [x] Add Signer A/B direct activation sender helpers that can POST to
            `/router-ab/v1/signing-worker/ecdsa-hss/activate` after private
            Deriver validation succeeds.
      - [x] Add pure SigningWorker direct-delivery aggregation/reconciliation
            rules so two Deriver deliveries produce exactly one aggregate
            activation request or a deterministic conflict.
      - [x] Wire SigningWorker route/DO handling so two independent direct
            delivery POSTs produce exactly one activated state or a deterministic
            conflict.
      - [x] Add source guards proving Deriver direct delivery cannot target the
            export route and cannot include client-recipient export bundles.
      - [x] Add Cloudflare binding/config validation and tests proving direct
            delivery is enabled only when both Deriver roles have an exact
            SigningWorker service binding.
- [x] Add Router-mediated activation relay as an optional restricted deployment
      profile using the same ciphertext.
- [x] Add SigningWorker activation handler that opens only ECDSA-HSS
      SigningWorker-targeted material and returns a public receipt.
- [x] Persist active ECDSA SigningWorker state by account, ECDSA threshold key
      id, signing root id/version, SigningWorker identity, and activation epoch.

### Phase 5: Explicit Export

- [x] Add Router export boundary with user-confirmation evidence, export nonce,
      expiry, and export authorization digest.
- [x] Add Deriver A/B export handlers that produce only client-recipient export
      bundles.
- [x] Ensure the SigningWorker does not release active ECDSA material for export.
- [x] Add client export reconstruction and verification rules:
      `x_export * G == X` and `ethereum_address(X) == expected_address`.
- [x] Add nonce replay protection and failure-burning behavior.
- [x] Add audit events that include operation kind, public key/address
      fingerprint, authorization digest, nonce fingerprint, and result.
      The public Router explicit-export handler emits an
      `EcdsaHssExplicitExportDecision` audit event for forwarded, stopped, and
      rejected outcomes.
- [x] Source-guard logs and telemetry against `x`, `x_client`, `x_server`,
      `privateKeyHex`, raw root material, and presign scalar material.
      Source guards keep the export audit event to public request metadata,
      authorization digest, decision, and reason code.

### Phase 6: Normal Signing Integration

- [x] Add active ECDSA-HSS normal-signing scope lookup and material binding:
      active state must match wallet id, ECDSA threshold key id,
      SigningWorker identity, activation transcript, and a re-derived public
      identity from persisted SigningWorker material.
- [x] Add Router-to-SigningWorker ECDSA-HSS EVM digest signing request shape
      because the Ed25519 Wallet Session V2 shape cannot carry the ECDSA
      activation identity.
- [x] Bind ECDSA-HSS EVM digest signing requests to active ECDSA SigningWorker
      state during materialization.
- [x] Keep A/B derivation handlers unreachable from the materialized ECDSA-HSS
      normal-signing boundary.
- [x] Add source guards proving the materialized normal-signing request cannot
      call ECDSA-HSS registration, export, recovery, or activation handlers.
- [x] Add the SigningWorker ECDSA-HSS finalize handler interface and helper that
      materializes active state and one-use presignature state before handler
      invocation.
- [x] Add Cloudflare-compatible one-use ECDSA presignature state with typed
      Durable Object put/take/cleanup, exact request-digest binding, admitted
      signing-digest binding, active SigningWorker binding, and scalar-share
      receipt redaction.
- [x] Bind ECDSA-HSS rerandomization entropy across the public prepare response,
      private one-use presignature record, and Durable Object put receipt.
- [x] Add the ECDSA-HSS finalize request boundary with server presignature id,
      32-byte client signature share, and prepare request-digest binding.
- [x] Add SigningWorker private ECDSA-HSS prepare fetch helper that materializes
      active state, invokes the ECDSA prepare handler, stores the one-use
      presignature record, validates the put receipt, and returns only the
      public prepare response.
- [x] Add Router public ECDSA-HSS prepare admission and service-call helper:
      verify Wallet Session against wallet id, ECDSA threshold key id, and
      SigningWorker id; derive Router-owned admission; reserve replay; and
      forward the trusted-admission-bearing request to SigningWorker.
- [x] Add SigningWorker private ECDSA-HSS finalize fetch helper that materializes
      active state, loads active material, takes the exact one-use presignature
      record, invokes the ECDSA finalize handler, and validates the public
      signature response against the prepare request.
- [x] Add Router public ECDSA-HSS finalize admission and service-call helper:
      verify Wallet Session against wallet id, ECDSA threshold key id, and
      SigningWorker id; derive Router-owned policy/quota/abuse admission for the
      exact finalize request; and forward only a trusted-admission-bearing
      finalize request to SigningWorker.
- [x] Wire strict public Router ECDSA-HSS prepare and finalize routes to the
      materialized request, Wallet Session boundary, and SigningWorker service
      calls.
- [x] Wire strict private SigningWorker ECDSA-HSS finalize dispatch to one-use
      presignature take and production finalize handling.
- [x] Implement the production ECDSA-HSS finalize handler that consumes
      Cloudflare-compatible presign state through `signer-core` and returns a
      recoverable secp256k1 signature bound to the exact request.
- [x] Require the ECDSA-HSS prepare request to carry the client-held
      presignature id, bind it into the request digest, carry it through Router
      prepare admission, and require the public prepare response to echo the
      selected server presignature id.
- [x] Implement production ECDSA-HSS prepare/presignature consumption for the
      SigningWorker through a covered one-use presignature cache populated
      before strict prepare reserves the selected presignature id.
- [x] Wire strict private SigningWorker ECDSA-HSS prepare dispatch to the
      pool-backed production path.
- [x] Add a typed SDK/server bridge that converts the existing public
      TypeScript threshold-ECDSA presignature output into the strict private
      SigningWorker ECDSA-HSS pool-fill request.
- [x] Add a producer-side sender for the strict private SigningWorker
      ECDSA-HSS pool-fill route with receipt validation and duplicate
      classification.
- [x] Wire the client-facing SDK/server ECDSA-HSS presignature producer path to
      carry validated Router A/B scope through presign-session state and invoke
      the pool-fill sender on presign completion.
- [x] Preserve existing ECDSA signing latency expectations.

### Phase 7: Recovery And Refresh

- [x] Define ECDSA-HSS recovery semantics under Router-A-B: recovery uses the
      export primitive, client-recipient recovery authorization, recovery nonce,
      recovery-specific transcript domain, and Deriver A/B client-output
      envelopes.
- [x] Define SigningWorker activation refresh after Deriver A/B root-share
      rotation.
      Refresh uses the refresh primitive, requires the current public identity,
      carries previous and next activation epochs, and derives SigningWorker
      activation material instead of client export material.
- [x] Verify public identity parity before and after refresh.
- [x] Invalidate stale SigningWorker activation state after rotation.
- [x] Add boundary rollback rejection for non-advancing activation epochs and
      keep stale activation rejection in the existing SigningWorker activation
      Durable Object path.
- [x] Add Cloudflare Deriver A/B private recovery and activation-refresh request
      handlers that derive only the recipient class allowed by each request.
- [x] Wire public Router ECDSA-HSS recovery endpoint to the private Deriver
      recovery handlers and client-recipient response aggregation.
- [x] Wire public Router ECDSA-HSS activation-refresh endpoint to a typed
      SigningWorker refresh activation path.

### Phase 8: Validation And Benchmarks

- [x] Add native core tests for all ECDSA-HSS Router-A-B boundary parsers.
- [x] Add vectors for registration, activation, export, recovery, wrong
      recipient, wrong Deriver identity, wrong SigningWorker identity, replay,
      expiry, and public-key/address mismatch.
- [x] Add source guards proving no production Router, Deriver, SigningWorker,
      log, audit, or public/persistence receipt path materializes canonical
      `x`; one-use presignature scalar shares remain confined to the private
      SigningWorker presignature storage records required by signing.
- [x] Add Cloudflare adapter tests and source guards for ECDSA-HSS boundary
      parsing, strict routing, registration activation, export non-activation,
      and public identity derivation.
- [x] Add Cloudflare tests/source guards for ECDSA-HSS client-only Deriver
      export responses, export private-route dispatch, and typed export
      request-to-payload binding.
- [x] Add Cloudflare tests/source guards for ECDSA-HSS active material binding
      before normal signing.
- [x] Add core and Cloudflare tests/source guards for ECDSA-HSS EVM digest
      signing request parsing, active-state materialization, and drift
      rejection.
- [x] Add core and Cloudflare tests/source guards for ECDSA-HSS recoverable
      signature response binding and handler materialization order.
- [x] Add Cloudflare tests/source guards for ECDSA-HSS one-use presignature
      storage, expiry, replay conflict, digest drift rejection, cleanup, and
      scalar-share receipt redaction.
- [x] Add native core tests for ECDSA-HSS finalize request parsing, unknown-field
      rejection, client-share length rejection, exact-expiry rejection, and
      prepare-digest binding.
- [x] Add core and Cloudflare tests/source guards for ECDSA-HSS prepare response
      binding, unknown-field rejection, server presignature point validation,
      private scalar-share redaction, and one-use presignature put receipt
      binding.
- [x] Add core and Cloudflare tests/source guards for ECDSA-HSS rerandomization
      entropy validation, response/record/receipt binding, strict Router
      prepare/finalize dispatch, strict SigningWorker finalize dispatch, and
      production recoverable signature output.
- [x] Add Cloudflare tests for unbound ECDSA-HSS presignature pool keying,
      one-use reserve/take semantics, and pool-backed prepare binding to the
      selected client presignature id.
- [x] Add Cloudflare tests/source guards for strict private ECDSA-HSS
      presignature pool-fill request validation, active-state derivation, and
      route dispatch.
- [x] Add TypeScript bridge validation for converting existing public
      threshold-ECDSA presignature output into the strict private ECDSA-HSS
      pool-fill wire shape, including invalid scope/share rejection and
      legacy-field rejection.
- [x] Add TypeScript sender validation for exact strict private pool-fill path,
      internal service-auth header propagation, success receipt parsing,
      duplicate receipt classification, and request/receipt drift rejection.
- [x] Add native core tests for ECDSA-HSS recovery and activation-refresh
      request parsing, lifecycle-kind rejection, envelope-role rejection,
      strict unknown-field rejection, recovery/export digest separation, and
      non-advancing activation epoch rejection.
- [x] Add native core validation that ECDSA-HSS recovery and activation-refresh
      requests convert into the generic Router proof-bundle transport with the
      expected nonce, lifecycle, recipient key, and Deriver A/B envelopes.
- [x] Add Cloudflare adapter validation for ECDSA-HSS recovery and
      activation-refresh private request wrappers, payload drift rejection,
      strict private route dispatch, and recipient-class separation.
- [x] Add Cloudflare adapter validation for public ECDSA-HSS recovery admission
      response construction, Router payload binding, and client-bundle ordering.
- [x] Add Cloudflare adapter validation for public ECDSA-HSS activation-refresh
      receipt construction, public-identity parity, material drift rejection,
      strict Router route dispatch, and distinct SigningWorker refresh route
      dispatch.
- [x] Benchmark registration/bootstrap latency.
- [x] Benchmark explicit export latency.
- [x] Benchmark ECDSA-HSS activation latency separately from normal signing.
- [x] Benchmark normal ECDSA signing latency and verify A/B adds no normal
      signing round trip.

### Phase 9: Final Legacy And Naming Cleanup

Run this phase only after the Wallet Session V2 and ECDSA-HSS Router A/B
functional plan is complete. The cleanup order matters: first delete every
legacy compatibility surface, then normalize names after there is only one active
model left.

The broader Router A/B-only signing cleanup plan lives in
[router-a-b-cleanup.md](./router-a-b-cleanup.md). It owns deletion of the old
non-Router `/threshold-ecdsa/*` public signing routes and SDK threshold-session
callers after ECDSA-HSS Router A/B signing coverage is complete.

Status: moved to [router-a-b-cleanup.md](./router-a-b-cleanup.md) Phase 11 and
its surrounding cleanup phases. Do not track this checklist in two files; close
the remaining final legacy and naming cleanup work from the cleanup plan.

## Release Acceptance Criteria

Cloudflare Router A/B deployment is allowed only after:

- [x] `router_ab_ecdsa_hss_secp256k1_v1` protocol ids, request kinds, transcript
      domains, wire shapes, and boundary parsers are frozen.
- [x] Router public ECDSA-HSS registration/bootstrap and export boundaries
      accept only typed, validated requests.
- [x] Deriver A/B private ECDSA-HSS export handlers derive only
      client-recipient export material.
- [x] Deriver A/B private ECDSA-HSS registration handlers derive only
      recipient-scoped SigningWorker activation material.
- [x] Deriver A/B private ECDSA-HSS recovery and refresh handlers derive only
      recipient-scoped recovery or refresh material.
- [x] SigningWorker activation and materialized ECDSA-HSS prepare/finalize
      requests bind to active ECDSA identity.
- [x] SigningWorker ECDSA-HSS presignature state is one-use, request-bound,
      digest-bound, active-state-bound, and cleaned up after expiry.
- [x] ECDSA-HSS finalize requests carry a 32-byte client signature share and bind
      back to the exact prepare request digest.
- [x] ECDSA-HSS prepare responses expose only the server presignature id, public
      presignature point, rerandomization entropy, request digest, signing
      digest, scheme, and timing.
- [x] Router and SigningWorker ECDSA-HSS finalize helpers admit the exact
      finalize request, consume the exact one-use presignature record, and
      validate the response against the prepare request.
- [x] Strict public Router routes use the materialized ECDSA-HSS prepare/finalize
      requests.
- [x] Strict private SigningWorker finalize uses the materialized ECDSA-HSS
      finalize request and one-use presignature state.
- [x] Production ECDSA-HSS finalize handler consumes the Cloudflare-compatible
      presign state and returns a response bound to the exact request digest.
- [x] Prepare request binding includes the client-selected presignature id, and
      the public prepare response must echo that id as the server presignature
      id.
- [x] Strict private SigningWorker prepare route uses pool-backed production
      ECDSA-HSS prepare/presignature supply, and strict private pool-fill can
      populate the unbound pool from a trusted producer.
- [x] Strict private Deriver and SigningWorker routes require internal
      service-auth before runtime construction or body parsing, non-Router
      Wrangler configs disable `workers_dev`, and Router service-binding calls
      attach the internal service-auth header.
- [x] Export reconstructs and verifies canonical `x` only in the authorized
      client export runtime.
- [x] Recovery semantics are defined, implemented, and covered at the strict
      Router/Deriver boundary.
- [x] Activation-refresh semantics are defined, implemented, and covered through
      the public Router and SigningWorker refresh activation path.
- [x] Source guards prove no production Router, Deriver, SigningWorker, log,
      audit, or public/persistence receipt path materializes canonical `x`,
      `privateKeyHex`, or raw root material; presign scalar shares remain
      confined to private SigningWorker request and storage records.
- [x] Local ECDSA-HSS hot-path signing, registration/bootstrap, export,
      recovery/refresh, native vectors, Wasm adapter tests, and Cloudflare
      boundary parser tests pass.
- [ ] Deployed strict Cloudflare evidence covers Ed25519 Wallet Session V2 and
      ECDSA-HSS Router A/B configured-origin success, rejected-origin behavior,
      preflight behavior, timing with preflight included, worker metrics/logs,
      and Deriver A/B non-invocation on normal signing.
- [x] Final cleanup ownership moved to
      [router-a-b-cleanup.md](./router-a-b-cleanup.md) Phase 11 and surrounding
      cleanup phases. Local Router A/B-only cleanup is complete there; deployed
      Cloudflare evidence remains the open release-tail item.

## Validation Evidence

Validation runs on June 15-16, 2026:

- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 40 tests after adding the ECDSA-HSS finalize request boundary.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 254 tests after adding ECDSA-HSS presignature Durable Object
  coverage.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 257 tests after adding protocol-specific ECDSA-HSS Deriver
  registration private requests and strict private routes.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 45 tests after adding the ECDSA-HSS prepare response boundary.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 261 tests after adding the ECDSA-HSS SigningWorker private
  prepare fetch helper and presignature response redaction coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 265 tests after adding Router public ECDSA-HSS prepare admission,
  trusted-admission-bearing SigningWorker requests, and Router prepare source
  guards.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after routing ECDSA-HSS registration through the protocol-specific
  Deriver service call.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after adding the ECDSA-HSS private prepare fetch helper.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after adding the ECDSA-HSS private prepare fetch helper.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after adding Router public ECDSA-HSS prepare admission.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after adding Router public ECDSA-HSS prepare admission.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 271 tests after adding ECDSA-HSS Router finalize admission,
  SigningWorker private finalize fetch, one-use presignature take, and service
  call coverage.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 45 tests after the Cloudflare finalize wiring.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after adding ECDSA-HSS finalize admission and service-call helpers.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after adding ECDSA-HSS private finalize fetch.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 46 tests after adding ECDSA-HSS rerandomization entropy to the
  prepare response boundary.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 272 tests after wiring strict public Router ECDSA-HSS
  prepare/finalize, strict private SigningWorker finalize, and production
  recoverable signature output.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after strict public Router ECDSA-HSS prepare/finalize dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after strict private SigningWorker ECDSA-HSS finalize dispatch.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 48 tests after making `client_presignature_id` required in the
  ECDSA-HSS prepare request and binding it into the canonical request digest.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 272 tests after carrying the ECDSA-HSS presignature selector
  through Router prepare admission and response binding.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after the ECDSA-HSS prepare request selector change.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after the ECDSA-HSS prepare request selector change.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 276 tests after adding the unbound ECDSA-HSS presignature pool,
  pool-backed strict private SigningWorker prepare dispatch, and
  request-bound prepare record creation from the reserved pool entry.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 279 tests after adding the strict private ECDSA-HSS
  presignature pool-fill request boundary and route dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring strict private SigningWorker ECDSA-HSS pool-fill route
  dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring strict private SigningWorker ECDSA-HSS pool-fill route
  dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring strict private SigningWorker ECDSA-HSS prepare dispatch
  to the pool-backed production wrapper.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring strict private SigningWorker ECDSA-HSS prepare dispatch
  to the pool-backed production wrapper.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed after adding the
  Router A/B ECDSA-HSS presignature bridge and sender.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts --reporter=line`
  passed with 6 tests after adding the Router A/B ECDSA-HSS presignature
  bridge and sender.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts ./unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`
  passed with 20 tests after wiring Router A/B ECDSA-HSS pool-fill through
  threshold-ECDSA presign-session state and completion.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 58 tests after adding strict ECDSA-HSS recovery and activation
  refresh request boundaries plus generic Router proof-bundle conversion.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 283 tests after adding strict Cloudflare ECDSA-HSS recovery and
  activation-refresh private Deriver wrappers and route dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after wiring strict Signer A/B ECDSA-HSS recovery and refresh private
  routes.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 284 tests after wiring the strict public Router ECDSA-HSS
  recovery route and public recovery admission response validation.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring the strict public Router ECDSA-HSS recovery route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after adding the public recovery route to the shared strict worker.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 287 tests after wiring the strict public Router ECDSA-HSS
  activation-refresh route, distinct private SigningWorker refresh route, and
  refresh public-identity parity validation.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 288 tests after adding Cloudflare source guards that reject
  canonical ECDSA-HSS export/private-key material in Router, Deriver,
  SigningWorker, public response, and receipt boundaries while preserving the
  private one-use SigningWorker presignature storage path.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 58 tests after adding the canonical ECDSA-HSS active-state
  session id and binding lifecycle validation to key id, signing root
  id/version, and activation epoch.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 289 tests after keying ECDSA-HSS active SigningWorker state and
  Wallet Session/admission validation by the canonical active-state session id.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`,
  `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`,
  `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`,
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after tightening ECDSA-HSS active-state keying.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring the public ECDSA-HSS activation-refresh route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring the private ECDSA-HSS SigningWorker refresh route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after adding refresh to the shared strict worker.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts --reporter=line`
  passed with 15 tests after confirming client-side ECDSA-HSS export
  reconstruction/verification, export nonce replay/failure-burning behavior,
  server/client WASM surface separation, and current threshold-prf fixture
  purpose wiring.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/thresholdEcdsa.behavior.guard.unit.test.ts --reporter=line`
  passed with 5 source-guard tests after adding the Router A/B ECDSA-HSS
  production bridge guard for export/root material and tightening the stale
  context-version guard to allow the active `RouterAbEcdsaHssStableKeyContextV1`
  boundary type.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 291 tests after adding explicit Signer A/B SigningWorker peer
  bindings and negative binding-role coverage.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.` after updating the release-ready guard
  to the current ECDSA-HSS strict-route symbols and Signer A/B SigningWorker
  service-binding config.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 296 tests after adding the direct single-bundle
  Deriver-to-SigningWorker activation delivery request type and rejection
  coverage for client-recipient, wrong-role, and wrong-context bundles.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 299 tests after adding deterministic direct-delivery aggregation
  coverage for reversed delivery order, duplicate Deriver role, and activation
  context conflict.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 300 tests after adding direct-delivery source guards for
  server-only bundle validation and client/export surface exclusion.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 71 tests on June 16 after adding Router protocol vectors for
  wrong Deriver identity and replay nonce digest binding across registration,
  export, recovery, and activation refresh.
- `rtk cargo test --manifest-path crates/ecdsa-hss/Cargo.toml --test role_local_mvp`
  passed with 9 tests on June 16, including public-key/address mismatch
  rejection during client-side export reconstruction.
- `rtk cargo test --manifest-path crates/signer-core/Cargo.toml --features threshold-ecdsa-hss,typescript-bindings --test native_readiness_vectors`
  passed with 1 native readiness vector replay on June 16.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 309 tests on June 16 after the strict Cloudflare ECDSA-HSS
  boundary, active-state, recovery, refresh, direct-delivery, and source-guard
  slices.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed on June 16 after the
  Router A/B ECDSA-HSS presignature bridge/sender lifecycle wiring.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/thresholdEcdsa.behavior.guard.unit.test.ts --reporter=line`
  passed with 5 tests on June 16.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts --reporter=line`
  passed with 6 tests on June 16.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts ./unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`
  passed with 20 tests on June 16.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts --reporter=line`
  passed with 15 tests on June 16.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`,
  `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`,
  `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`,
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed on June 16.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.` on June 16.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
  passed on June 16.
- `rtk pnpm benchmark:ecdsa-hss:wasm` passed on June 16 after updating the
  benchmark runner to use the active
  `prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1`,
  `finalize_ecdsa_client_bootstrap_v1`, and
  `build_ecdsa_role_local_export_artifact_v1` WASM command surface. The run
  wrote
  `benchmarks/ecdsa-hss-wasm/out/2026-06-16T05-14-03-679Z/summary.md` with
  median timings of 0.088 ms for client prepare, 0.049 ms for client finalize,
  0.199 ms for server bootstrap, 0.306 ms for full bootstrap, 0.101 ms for
  export artifact generation, and 0.1 ms for browser client prepare.
- The old threshold-ECDSA presign benchmark has been retired. It still measured
  deleted `/threshold-ecdsa/*` public signing routes, so it is no longer valid
  Router A/B ECDSA-HSS release evidence. Router A/B ECDSA-HSS normal-signing
  timing now requires a replacement harness that exercises the Router A/B
  prepare/finalize and pool-fill routes directly.
- `rtk cargo bench --manifest-path crates/router-ab-cloudflare/Cargo.toml --bench router_latency -- router_ab_ecdsa_hss_activation_storage_v1 --sample-size 10 --warm-up-time 1 --measurement-time 2`
  passed on June 16 after adding the local SigningWorker-output activation
  storage benchmark. The measured
  `router_ab_ecdsa_hss_activation_storage_v1/activate_and_lookup_active_state`
  path, including in-memory activation storage and active-state lookup, reported
  `time: [128.89 µs 129.51 µs 130.44 µs]`.
- `rtk pnpm router:deploy:dry-run -- --env staging` passed on June 16 after
  setting the worker-build WASM C compiler to the Homebrew LLVM clang when the
  local shell has not set `CC_wasm32_unknown_unknown`. The run wrote
  `crates/router-ab-cloudflare/reports/startup-latencies/startup-latencies-2026-06-16T05-38-33-964Z.json`
  with Router 2887.88 KiB / gzip 879.45 KiB, Deriver A 2336.55 KiB / gzip
  737.40 KiB, Deriver B 2336.49 KiB / gzip 738.38 KiB, and SigningWorker
  2784.06 KiB / gzip 896.44 KiB.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed with 20 tests on June 16 after removing client-supplied
  `group_public_key` from v2 normal-signing finalize wire material.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed with 38 tests on June 16 after adding strict private service-auth and
  export-audit source guards.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed with 273 tests on June 16 after binding Ed25519 finalize group-key
  ownership to active SigningWorker state.
- `rtk pnpm -C packages/sdk-web type-check` and
  `rtk pnpm -C packages/sdk-server-ts type-check` passed on June 16 after the
  v2 normal-signing wire change and Router A/B ECDSA-HSS bridge rename to
  `serverKeyId`.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts --reporter=line`
  passed with 19 tests on June 16 after switching strict private pool-fill to
  the internal service-auth header.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`,
  `strict-worker-signing-worker-entrypoint`, `strict-worker-signer-a-entrypoint`,
  and `strict-worker-signer-b-entrypoint` passed on June 16 after adding the
  Worker-only internal service-auth and export-audit code.
- `rtk pnpm router:deploy:check` passed on June 16 after adding release guards
  for non-Router `workers_dev = false`, strict private service-auth checks, and
  Router-to-private service-auth headers.

## Open Decisions

- Should `router_ab_ecdsa_hss_secp256k1_v1` preserve existing role-local ECDSA
  key identity or require fresh ECDSA keys?
- Should ECDSA-HSS export always rederive export material from Deriver A/B, or
  can a hardened deployment allow SigningWorker export under stronger policy?
- Which public proof is enough to bind `X_server` to A/B output without
  leaking `x_server` to Router or a Deriver?
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

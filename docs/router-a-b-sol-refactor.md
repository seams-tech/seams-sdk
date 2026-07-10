# Router A/B Ed25519 Yao And ECDSA Strict Refactor Plan

Date created: July 10, 2026

Status: approved implementation plan. Phase 0 closed on July 10, 2026. The
current Ed25519 hidden-evaluation backend is scheduled for deletion, and no
further succinct-HSS implementation work is authorized. Production release is
blocked until the actively secure Streaming Yao path, strict Router A/B cutover,
legacy deletion, independent deployment, and security gates in this plan are
complete.

Companion documents:

- [Router A/B specification](./router-a-b-SPEC.md)
- [Router A/B deployment reference](./router-a-b-deployment.md)
- [Router A/B local development](./router-a-b-local-dev.md)
- [Router A/B cleanup history](./router-a-b-cleanup.md)
- [Ed25519 HSS derivation](../crates/ed25519-hss/specs/derivation.md)
- [Ed25519 HSS protocol](../crates/ed25519-hss/specs/protocol.md)
- [Optimization 8](../crates/ed25519-hss/docs/optimization-8.md)
- [Streaming Yao for Deriver A and Deriver B](./yaos-ab.md)

Optimization 8 owns latency experiment evidence. This plan owns protocol
correctness, security, strict Router A/B integration, product migration,
operational segregation, and deletion of obsolete implementations.

The critical risk register, bounded construction shortlist, kill criteria, and
Ed25519 platform fallback ladder in `yaos-ab.md` are authoritative here. Phase
3A converts that evidence into the product-level construction and platform
decision. Downstream phases cannot bypass it.

## Goal

Make strict Router A/B the only SDK/server architecture for every Ed25519 and
ECDSA lifecycle:

- registration and bootstrap;
- SigningWorker activation;
- normal signing;
- presignature or nonce-pool fill;
- recovery and material restore;
- explicit key export;
- server-share or role-share refresh;
- add-signer and related wallet lifecycle operations.

The Ed25519 flow must preserve the standard export-compatible derivation:

```text
d = LE32(y_client + y_server mod 2^256)
h = SHA-512(d)
a = LE256(clamp(h[0..32])) mod l
```

The output projection must remain:

```text
tau = tau_client + tau_server mod l
x_client_base = a + tau mod l
x_server_base = a + 2 * tau mod l
a = 2 * x_client_base - x_server_base mod l
```

The refactor must also delete `ThresholdSigningService`. ECDSA-HSS does not get
an extracted replacement service or compatibility fallback. Existing strict
ECDSA Router A/B components are the target owners for every remaining ECDSA
responsibility.

## Executive Decisions

1. **Strict Router A/B is the only production topology.** Router performs
   admission, replay protection, policy, lifecycle tracking, and opaque routing.
   Deriver A and Deriver B perform role-local derivation. SigningWorker owns
   activated signing state and signing-time preprocessing.
2. **Ed25519 uses one exact protocol, `router_ab_ed25519_yao_v1`.** It computes the
   canonical seed, SHA-512 expansion, clamped scalar, and signing-share
   projection through actively secure Streaming Yao between fixed Deriver A
   garbler and Deriver B evaluator roles. Runtime selection between Ed25519
   derivation candidates is not a product feature.
3. **`mpc_threshold_prf_v1` is ECDSA-only.** Its independently
   derived client and server scalar outputs have no canonical seed and cannot
   provide standard Ed25519 key export. ECDSA retains strict Router A/B
   threshold-PRF derivation and additive secp256k1 scalar shares.
4. **The current `ed25519-hss` backend is deleted after replacement.** Formula-derived artifact
   sizes, deterministic padding, revealing commitments, joined-share objects,
   and same-process reconstruction are not retained in production code. No
   further succinct-HSS kernel, amplification, or optimization work proceeds.
5. **ECDSA also completes the strict cutover.** The existing strict
   `router-ab-core::protocol::ecdsa_hss` and SigningWorker architecture absorb
   all remaining generic service, authorization, pool, recovery, export, and
   refresh responsibilities.
6. **Production uses independent operators.** ECDSA requires
   `router_ab_cloudflare_separate_accounts_v1`. Ed25519 prefers that Worker
   profile and may use the Phase 3A-approved separate-account Containers or
   independent native-service fallback. Same-account bindings are limited to
   local development, staging, and performance evaluation.
7. **The production security target is privacy and correctness-with-abort
   against Router plus at most one malicious Deriver.** The selected fixed-
   circuit Yao construction requires a reviewed active-security compiler,
   malicious OT, input provenance and consistency, selective-failure
   resistance, and authenticated private outputs before production.
8. **The cutover is destructive.** Old ceremony records, session shapes, route
   bodies, feature branches, tests, fixtures, and fallback code are deleted.
   Every existing development Ed25519 wallet is reprovisioned under the frozen
   Yao-era stable context. No compatibility or conversion path is retained.
9. **Ed25519 Yao development starts in isolated Rust crates.** The exact oracle
   and generator live in `tools/ed25519-yao-generator`; production protocol
   manifests and later cryptographic code live in `crates/ed25519-yao`.
   Router, Cloudflare, SigningWorker, persistence, route, and SDK integration
   remain deferred until the isolated security and circuit gates pass.

## Non-Goals

- A generic garbling or MPC framework.
- A runtime-pluggable production backend registry.
- Compatibility with unfinished legacy ceremonies or old sealed session
  records.
- A fallback from strict Router A/B to TypeScript threshold routes.
- A quorum larger than two Derivers in this refactor.
- Fairness or guaranteed availability when either Deriver aborts.
- Protection after Deriver A and Deriver B collude.
- A rewrite of normal signing algorithms whose strict Router A/B implementation
  already satisfies the target ownership model.

## Non-Negotiable Invariants

### Canonical Ed25519 Identity

- `d` is exactly 32 little-endian bytes obtained from addition modulo
  `2^256`.
- SHA-512 consumes exactly the standard Ed25519 seed bytes.
- Clamping follows the standard Ed25519 pruning rules.
- Export releases the exact seed `d`, never a scalar-native substitute.
- Importing the exported seed reproduces the registered Ed25519 public key.
- Refresh preserves `d`, `a`, the public key, and address unless the operation
  is explicitly classified as wallet-key rotation.

### Role Separation

- Router never opens Deriver input envelopes or output-share packages.
- Deriver A cannot represent or reconstruct Deriver B's private input.
- Deriver B cannot represent or reconstruct Deriver A's private input.
- No production type contains both sides of `y`, `tau`, `d`, `a`,
  `x_client_base`, or `x_server_base`.
- SigningWorker receives only shares addressed to its current identity and
  activation epoch.
- Client receives only client-addressed output shares or explicitly authorized
  export shares.
- TypeScript receives opaque ciphertext, handles, public metadata, and receipts;
  it does not receive raw signing or derivation material.

### ECDSA Threshold-PRF And Additive-Share Ownership

- Every ECDSA bootstrap, signing, pool-fill, export, recovery, and refresh call
  enters through a strict Router A/B public route.
- Deriver A and Deriver B evaluate the strict ECDSA threshold PRF under stable,
  role-local root material and derive additive secp256k1 scalar shares.
- The client and SigningWorker scalar shares satisfy
  `x = x_client + x_server mod n`; public-point parity is verified before
  activation and export.
- Deriver A and Deriver B own only role-local ECDSA derivation material.
- SigningWorker owns active ECDSA server signing shares and server
  presignatures.
- Browser/WASM owns client ECDSA shares and client presignature material.
- No `ThresholdSigningService`, ECDSA-specific successor service, or old
  threshold route remains reachable.

### Ed25519 Export

- Export is a distinct request branch with step-up authorization.
- Export authorization binds wallet/key identity, operation, recipient key,
  transcript, expiry, and one-use nonce.
- Each Deriver validates export authorization independently.
- Export releases additive seed contributions only to the authorized client.
- The client reconstructs `d`, recomputes the public key, and requires equality
  with the registered key before returning an exported key.
- Export authorization is consumed even if client delivery or local import
  validation fails after release.

### Deployment

- Deriver A and Deriver B use separate administrative domains, deploy
  principals, secrets, persistence, backups, logs, audit exports, and
  approvers. ECDSA and the preferred Ed25519 profile use separate Cloudflare
  accounts and Durable Object namespaces.
- No human, CI principal, API token, break-glass credential, or secret store can
  administer both Derivers.
- A and B authenticate direct peer messages with distinct asymmetric keys.
- Router and SigningWorker have no access to either Deriver root store or
  envelope decryption key.
- A Phase 3A Ed25519 platform fallback requires a new deployment profile,
  constant-time and compiled-output review, erasure analysis, placement and cost
  evidence, and independent approval. It cannot weaken the cryptographic or
  operator-separation claim.

## Current-State Gap Matrix

| Requirement                                                                      | Intended source                          | Current implementation evidence                                                                                                                 | Classification                  | Confidence | Owning phase |
| -------------------------------------------------------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- | ---------: | ------------ |
| Ed25519 derivation uses strict A/B role processes                                | `router-a-b-SPEC.md` Sections 2-5        | `/router-ab/ed25519/hss/*` dispatches to `ThresholdSigningService` in `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts` | Critical mismatch               |     `0.99` | 5, 7, 10     |
| Ed25519 identity derives from canonical `d`                                      | `crates/ed25519-hss/specs/derivation.md` | `router-ab-core` selects independent `x_client_base` and `x_server_base` threshold-PRF purposes                                                 | Critical mismatch               |     `0.99` | 1, 5         |
| Neither peer obtains both share sides                                            | `router-a-b-SPEC.md` Section 3           | `DdhHssSharedWord` and client/server delivery APIs carry both sides                                                                             | Critical mismatch               |     `0.99` | 3B, 4        |
| Actively secure Streaming Yao is implemented                                     | `yaos-ab.md`                             | No fixed-circuit active Yao crate, malicious OT, input binding, or authenticated private-output implementation exists                           | Critical missing implementation |     `0.99` | 2, 3A, 3B, 4 |
| Production uses independent operators                                            | Deployment intent                        | Active deployment documentation and bindings still prioritize same-account Service Bindings                                                     | High missing implementation     |     `0.97` | 6, 11        |
| ECDSA threshold-PRF/additive shares use strict Router A/B only                   | Router A/B spec                          | Strict ECDSA components exist, while generic service getters and threshold route handlers remain reachable                                      | High partial match              |     `0.96` | 5, 8, 10     |
| One malicious Deriver cannot corrupt or selectively fail the protocol undetected | Target threat model                      | No active Yao compiler, malicious OT, input consistency, or authenticated private-output composition exists                                     | Critical missing implementation |     `0.95` | 3A, 3B, 4, 9 |

This matrix is the initial implementation baseline. Each phase updates the
corresponding row with code, tests, and evidence. A partial match does not count
as release completion.

## Target Architecture

```mermaid
flowchart LR
  C["Browser / client WASM"] -->|"public request + opaque A/B envelopes"| R["Router"]
  R -->|"A envelope"| A["Deriver A administrative domain"]
  R -->|"B envelope"| B["Deriver B administrative domain"]
  A <-->|"signed transcript-bound secure-computation messages"| B
  A -->|"opaque recipient ciphertexts A"| R
  B -->|"opaque recipient ciphertexts B"| R
  R -->|"encrypted client package set"| C
  R -->|"encrypted server package set"| SW["SigningWorker"]
  SW -->|"activation receipt / signing response"| R
```

Router-mediated ciphertext relay is the sole target product topology. The large
garbled stream remains direct between A and B. Router carries only compact
recipient ciphertexts and public receipts and cannot decrypt or combine them.

Normal signing after activation remains:

```text
Client -> Router -> SigningWorker -> Router -> Client
```

Deriver A and Deriver B participate only in derivation-time ceremonies,
recovery, export, refresh, or activation. They remain outside the normal signing
latency path.

## Target Source Ownership

```text
tools/ed25519-yao-generator
  exact clear reference functionality and vectors
  deterministic circuit compiler and liveness schedule generator
  developer/CI artifact emission
  no production reverse dependency

crates/ed25519-yao
  validated fixed protocol and circuit manifests
  reviewed embedded production artifacts
  actively secure garbler/evaluator, OT, and private-output protocol
  no clear joined evaluator or generator dependency

crates/router-ab-core
  public request and authorization contracts
  typed Ed25519 Yao and ECDSA lifecycle states
  canonical transcript and wire metadata
  recipient and role identities
  replay/error/output receipt contracts
  no secret-processing implementation

crates/router-ab-ed25519-yao
  production adapter between router-ab-core contracts and ed25519-yao roles
  no Router, HTTP, Cloudflare, persistence, or browser policy

crates/router-ab-cloudflare
  public Router Worker
  Deriver A Worker adapter
  Deriver B Worker adapter
  SigningWorker adapter
  role-local Durable Objects
  signed cross-account HTTPS transport

crates/signer-core and browser WASM
  client input derivation and splitting
  recipient-envelope construction
  client output combination
  explicit seed export reconstruction and verification
  client Ed25519 and ECDSA signing material

packages/sdk-web
  public lifecycle orchestration
  worker handles and public metadata
  no raw crypto material

packages/sdk-server-ts
  application auth integration and scoped Router grant issuance
  no threshold signing or hidden-evaluation service
```

The new adapter crate is deferred until Phase 5. The first implementation slice
creates only `tools/ed25519-yao-generator` and `crates/ed25519-yao`; Router,
Cloudflare, SigningWorker, persistence, SDK, and route code remain untouched.
When composition begins, `router-ab-core` stays cryptography-agnostic,
`ed25519-yao` stays transport-agnostic, and one adapter owns production
composition.

## Domain-State Rules

- Use distinct Rust enums for Ed25519 registration, export, recovery, refresh,
  and activation requests.
- Use distinct role-local state types for Deriver A and Deriver B.
- Use consuming transitions for secret lifecycle state. Finalization accepts
  owned state and cannot be called twice.
- Model preprocessing as:

  ```text
  Available -> Reserved -> Consumed
                       -> Destroyed
  ```

- An uncertain crash destroys the affected one-use material.
- Export types can carry `SeedExportShare`; every non-export request type makes
  that field impossible.
- Client-output and SigningWorker-output branches use distinct recipient types.
- Raw request bodies, persisted records, and worker responses are validated once
  at their boundary and converted to precise internal types.
- Boundary compatibility shapes do not enter core logic.
- All switches over protocol, request, recipient, role, and lifecycle unions are
  exhaustive.
- Add compile-time fixtures that reject missing identity, broad-spread
  construction, wrong-recipient fields, mixed protocol branches, reusable
  consumed state, and legacy service inputs.

## Root And Key-Continuity Policy

The development cutover performs an unconditional hard identity reset for every
existing Ed25519 wallet. Each wallet is reprovisioned under one new, frozen
Yao-era `StableKeyDerivationContext`. Old records are invalidated. No migration,
address-preserving conversion, runtime compatibility flag, or retained HSS
backend exists.

The SDK-owned Ed25519 Yao application binding is frozen before the stable
context is constructed:

```text
LP32(x) = BE32(byte_length(x)) || x

application_binding_domain =
    ASCII("seams/router-ab/ed25519-yao/application-binding/v1")

Ed25519YaoApplicationBindingV1 =
    LP32(application_binding_domain)
    || LP32(ASCII("walletId"))
    || LP32(UTF8(walletId))
    || LP32(ASCII("nearEd25519SigningKeyId"))
    || LP32(UTF8(nearEd25519SigningKeyId))
    || LP32(ASCII("signingRootId"))
    || LP32(UTF8(signingRootId))
    || LP32(ASCII("keyCreationSignerSlot"))
    || LP32(BE32(keyCreationSignerSlot))

application_binding_digest = SHA-256(Ed25519YaoApplicationBindingV1)
```

The string values contain one or more visible ASCII bytes in the inclusive
range `0x21..=0x7e`; spaces, control bytes, non-ASCII code points, trimming, and
Unicode normalization are outside the version-one grammar. Their byte lengths
fit unsigned 32-bit integers. SDK integration constructs them from authenticated
domain records through matching parsers. `keyCreationSignerSlot` is a positive
unsigned 32-bit integer. It is the immutable slot chosen when this wallet key is
created. Same-root recovery retains it, while changing it creates a new `d` and
public key. A new recipient for the same logical key retains the original
key-creation slot and records the recipient slot in ceremony/provenance data.

The binding excludes `nearAccountId`; the implicit-account case derives it from
the final public key, so including it would be circular. It also excludes
`signingRootVersion`, deployment/root/key/activation epochs,
lifecycle/request/auth/transport/ticket values, and mutable active, default, or
recipient signer slots.

The committed fixture `{wallet-fixture, ed25519ks_fixture,
project-fixture:env-fixture, keyCreationSignerSlot=1}` has application digest
`b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121`.
With participant identifiers `1` and `2`, its stable-context binding is
`b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655`
and its final KDF public key is
`ccd255d0b88721771947038f1a7c29b49eee3902d6aa732e5e448251537bf077`.
The canonical encoding bytes are committed in
`tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json`.

For newly provisioned Ed25519 wallets:

- Deriver A and Deriver B each own stable, independent derivation material or
  stable per-account role-local material.
- Their role-local contributions algebraically define `y_server` and
  `tau_server`.
- The exact KDF, labels, context fields, endianness, and reduction rules are
  frozen in Phase 1 vectors.
- Deployment, HPKE, peer-signing, and storage-encryption epochs are transcript
  metadata. They do not change the wallet derivation context.

Operational rotation taxonomy:

- Rotating deployment, transport, HPKE, signing, wrapping, or storage keys keeps
  wallet identity stable.
- Rewrapping an existing derivation root without changing its bytes keeps wallet
  identity stable.
- Refreshing correlated role-local account shares preserves their joined `y`,
  `tau`, `d`, and public key.
- Replacing derivation roots changes wallet keys and is an explicit wallet-key
  rotation.

Ed25519 recovery has one version-one identity-preserving form: rewrap the same
logical 32-byte client derivation root under the replacement credential. It
retains the stable application binding, including the immutable
key-creation signer slot, and rederives identical client contributions. The
server contributions remain unchanged. Fresh protocol coins, activation
packages, ticket, and activation epoch yield the same `d`, `a`, `tau`, scalar
bases, public points, and registered public key. Admission suspends the old
credential; successful activation promotes the replacement and tombstones the
old binding. An unavailable or compromised root requires an explicit wallet
rekey with a new public identity. Production root custody and same-root input
proof remain stop-ship work.

Ed25519 refresh keeps all roots, stable context, and client contributions fixed.
It applies explicit nonzero correlated deltas to the effective persisted server
contributions:

```text
y_server_A'   = y_server_A + delta_y mod 2^256
y_server_B'   = y_server_B - delta_y mod 2^256
tau_server_A' = tau_server_A + delta_tau mod l
tau_server_B' = tau_server_B - delta_tau mod l
```

The refresh lifecycle is `Active(current) -> Prepared(next) ->
OutputCommitted(next) -> WorkerActivated(next) -> Active(next) +
RetiredTombstone(current)`. A pre-output-commit abort discards the prepared next
epoch. From output commit onward, the refresh transition advances forward-only
and may redeliver only the exact committed ciphertexts. Re-evaluation with new
randomness, delta replacement, and rollback are forbidden. Partial cutover
freezes new derivation admission until worker activation; stale role/worker
epochs are then rejected. This is an identity-preserving static-corruption
transition. It carries no proactive or mobile-adversary healing claim. Joint
delta generation and anti-bias, delta custody/provenance, active-output
generation, and atomic distributed persistence remain stop-ship work.

ECDSA key continuity is frozen separately through existing strict ECDSA public
key and signing vectors. Moving an ECDSA lifecycle from
`ThresholdSigningService` to strict Router A/B must preserve its public key or be
classified as explicit wallet-key rotation.

## Security Target

Production targets:

```text
privacy and correctness-with-abort against Router plus at most one malicious
Deriver, under static corruption and no A+B collusion
```

Explicit exclusions:

- Deriver A and Deriver B collusion;
- sequential compromise of both role states without proactive refresh and
  verified erasure;
- client and SigningWorker collusion, because together they can reconstruct
  `a = 2*x_client_base - x_server_base`;
- platform compromise spanning both independent administrative domains;
- a common software-supply-chain compromise approved by both independent
  deployers;
- availability, fairness, and protection from a Deriver that always aborts.

The minimum passive/semi-honest construction may be used only as an isolated
research milestone. Product capability responses and documentation must not
advertise the hardened claim until the active-security phase and audit pass.

## Phase Overview

| Phase | Name                                              | Depends on                  | Exit result                                            |
| ----: | ------------------------------------------------- | --------------------------- | ------------------------------------------------------ |
|     0 | Freeze contract and stop-ship status              | None                        | Approved scope, threat model, budgets, identity policy |
|     1 | Freeze functionality, vectors, and party views    | Phase 0                     | Canonical Ed25519/ECDSA identity and lifecycle oracle  |
|     2 | Build isolated Yao oracle and circuit foundations | Phase 1                     | Exact vectors, manifests, and deterministic artifacts  |
|    3A | Decide active construction and platform           | Phase 1 and Phase 2 counts  | Signed decision record and reissued budgets            |
|    3B | Build the actively secure Streaming Yao core      | Phases 2 and 3A             | Role-local production construction                     |
|     4 | Add one-use role and preprocessing protocol       | Phase 3B                    | Malicious privacy/correctness-with-abort candidate     |
|     5 | Add strict Router A/B protocol integration        | Phases 1 and 4              | Typed Ed25519 and ECDSA strict lifecycle contracts     |
|     6 | Implement selected independent runtime profiles   | Phases 3A and 5 wire freeze | Signed cross-domain A/B execution                      |
|     7 | Migrate Ed25519 product lifecycles                | Phases 5-6                  | All Ed25519 flows use strict Router A/B                |
|     8 | Complete ECDSA strict migration                   | Phases 5-6                  | All ECDSA flows use strict Router A/B                  |
|     9 | Security, constant-time, and performance gates    | Phases 3B-8                 | Auditable release evidence                             |
|    10 | Hard cutover and legacy deletion                  | Phases 7-9                  | One implementation; generic service deleted            |
|    11 | Independent production evidence and release       | Phase 10                    | Signed two-operator release evidence                   |

### Cross-Plan Phase Crosswalk And Status Rules

`yaos-ab.md` owns the fine-grained Ed25519 Yao phase gates. This plan owns the
wider Ed25519/ECDSA product migration and cleanup gates. The formal-verification
plan owns proof readiness and evidence. A checked task means only that exact
foundation exists; it cannot bypass a blocked dependency or phase exit gate.

| This plan | Authoritative Yao phases | Formal-verification phases |
| --------- | ------------------------ | -------------------------- |
| 0         | 0                        | planning only              |
| 1         | 1                        | FV0-FV1                    |
| 2         | 1-3 foundation slice     | FV2-FV4                    |
| 3A        | 6A                       | decision gate before FV5   |
| 3B        | 4-6B                     | FV5-FV6                    |
| 4         | 7                        | FV7                        |
| 5         | 8                        | FV7                        |
| 6         | 9-10                     | FV8                        |
| 7         | 11                       | FV7-FV8 evidence           |
| 8         | 12                       | outside Ed25519 Yao proofs |
| 9         | 13                       | FV8                        |
| 10        | 14                       | FV9                        |
| 11        | 15                       | FV10                       |

Current status is aligned across plans: Phase 0 is closed and Phase 1 is in
progress. This plan's Phase 2 remains blocked on Phase 1. Its existing isolated
oracle, identifiers, draft manifests, and tests are partial foundation work and
do not open circuit synthesis, passive Yao, active protocol, or integration.

## Phase 0: Freeze Contract And Stop-Ship Status

Status: **complete — closed July 10, 2026; production gates remain active**

Goal: make the intended security and identity contract authoritative before new
cryptographic or routing code is written.

### TODO

- [x] Classify the current `ed25519-hss` candidate, artifact, DDH, joined
      client/server, and joined runtime paths as historical research inputs
      scheduled for deletion.
- [x] Remove the current prime-order implementation from production-security
      consideration.
- [x] Update `router-a-b-SPEC.md` so Ed25519 targets
      `router_ab_ed25519_yao_v1` and never uses `mpc_threshold_prf_v1`.
- [x] Update `router-a-b-deployment.md` so the initial strict profile is
      `router_ab_cloudflare_separate_accounts_v1`; classify same-account Service
      Bindings as local/staging-only. Phase 3A owns any new fallback profile and
      corresponding normative deployment update.
- [x] Record the hardened security claim, corruption matrix, explicit
      exclusions, and required active-security compiler.
- [x] Freeze unconditional Ed25519 development-wallet reprovisioning under one
      new stable Yao-era context. No compatibility or secure-conversion path is
      retained.
- [x] Confirm ECDSA identity remains governed by its existing strict protocol
      vectors; no ECDSA derivation change is introduced by Yao.
- [x] Freeze initial provisional p50, p95, payload, Worker memory, cold-start,
      round-trip, preprocessing-storage, and correctness-error budgets pending
      the Phase 3A reissue.
- [x] Freeze actively secure Yao as the only production security level. Passive
      artifacts are isolated measurement inputs and have no product entrypoint.
- [x] Assign generic-service inventory and source-guard work to the integration
      and deletion phases; the first slice does not edit overlapping SDK code.
- [x] Add this plan and `yaos-ab.md` to the active architecture set.

### Exit Gate

- [x] Security claim and party-corruption matrix are approved.
- [x] Key-continuity and root-refresh policy are approved for the development
      cutover.
- [x] Product resource budgets are recorded before prototype measurement.
- [x] Documentation no longer claims the current backend meets the target.
- [x] Every generic-service caller category has a target owner and deletion
      phase; the exact source inventory remains an integration deliverable.

Release remains a no-go while party views, active-security details, exact
resource evidence, or independent review are unresolved.

## Phase 1: Freeze Functionality, Vectors, And Party Views

Status: **in progress — isolated host-semantic types, a metadata-only activation
continuation, and four-case continuity evidence exist; full lifecycle evaluators
and party views remain open**

Goal: define exact executable semantics independently from any secure-computation
backend.

### TODO

- [x] Move the exact correctness oracle into
      `tools/ed25519-yao-generator`, with no `ed25519-hss` dependency.
- [x] Define `VectorClearReferenceTraceV1` fixtures containing the complete
      stable-context record, A/B inputs, joined test-only `y_A`, `y_B`, `d`,
      SHA-512 digest, clamped and reduced `a`, `tau_A`, `tau_B`, `tau`, both
      unshared scalar bases, public commitments, public key, and export seed.
- [x] Freeze stable-context fields, canonical encoding, endianness, reductions,
      participant identifiers, and domain separators.
- [x] Freeze the visible-ASCII identifier grammar, LP32 Yao-only
      application-binding preimage, and golden vector over wallet ID, Ed25519
      signing-key ID, logical signing-root ID, and immutable key-creation signer
      slot; exclude circular/mutable fields.
- [x] Freeze role-local contribution KDF labels and bind the stable context into
      those KDFs.
- [ ] Extract fixed encodings, KDFs, vectors, circuit/wire identifiers,
      lifecycle tables, deployment profiles, and release SLOs into the
      versioned normative specifications owned by `yaos-ab.md`.
- [ ] Make CI regenerate prose golden bytes and digests from
      `tools/ed25519-yao-generator` and fail on specification/code drift.
- [x] Add standard RFC 8032 seed import/export and signature-parity vectors.
- [x] Add deterministic pseudorandom differential vectors against an
      independent implementation.
- [x] Add carry-heavy addition cases.
- [x] Add clamp-boundary and scalar-reduction edge cases.
- [x] Verify `a = 2*x_client_base - x_server_base mod l` for every committed
      vector.
- [x] Verify exported `d` reproduces the registered public key and standard
      signature behavior.
- [x] Add host-only refresh before/after vectors proving exact opposite
      role-local deltas while preserving joined `d`, `a`, `tau`, scalar bases,
      public points, and `A_pub`.
- [ ] Freeze ECDSA strict identity, bootstrap, presign, signature, export,
      recovery, and refresh vectors before moving residual service callers.
- [x] Freeze request-kind-specific pre-state, success, output-custody, and
      identity boundary contracts for Ed25519 registration, activation,
      recovery, refresh, and export.
- [x] Implement the nonserializable five-branch host-semantic type layer.
- [x] Implement the metadata-only activation continuation for registration-,
      recovery-, and refresh-origin synthetic package references, with semantic
      binding checks, origin-specific promotion, and zero reference work.
- [x] Commit and independently reproduce the narrow four-case
      recovery/activation/refresh/activation lifecycle-continuity corpus.
- [x] Freeze same-root recovery plus explicit-delta refresh with pre-commit
      abort and post-commit forward-only cutover semantics.
- [x] Freeze the proof-system-neutral role-input provenance statement, A/B pair
      invariants, lifecycle evidence slots, epoch meanings, and registration
      anti-bias requirements in
      `tools/ed25519-yao-generator/docs/input-provenance-v1.md`.
- [ ] Close root/delta custody and provenance, joint delta generation and
      anti-bias mechanism, active-output generation, and atomic
      distributed-persistence blockers required for executable lifecycle ideal
      functionalities.
- [ ] Define Deriver anti-bias against adaptive inputs, selective abort, and
      retry after peer-dependent information. Treat client vanity-key grinding
      as an explicit authenticated admission policy with wallet, organization,
      and tenant limits when allowed.
- [ ] Write corresponding ECDSA lifecycle functionality and ownership maps by
      referencing the existing strict ECDSA protocol.
- [x] Freeze the common-leakage and output-custody boundary for Client, Router,
      Deriver A, Deriver B, SigningWorker, observers, and logs.
- [ ] Specify complete role-private inputs, randomness, frames, persistence
      views, abort equivalence, and each supported corruption set.
- [x] Record every allowed output and every forbidden joined value per role.
- [x] Freeze semantic transcript fields, recipient identities, derived circuit
      mapping, and public epoch categories.
- [ ] Freeze canonical transcript encoding, direction tags, sequence numbering,
      exact circuit/backend digests, and signed receipt bytes.
- [ ] Create an alignment matrix from each Router A/B invariant to its planned
      enforcement code and test.

### Exit Gate

- [ ] Two independent Ed25519 implementations agree with every canonical and
      randomized vector.
- [ ] Standard seed export/import parity passes.
- [ ] ECDSA vectors identify every value that must remain stable through the
      strict migration.
- [ ] Ideal functionality, party views, and transcript schema receive protocol
      review.
- [ ] No backend-specific assumption appears in the reference oracle.

## Phase 2: Build Isolated Yao Oracle And Circuit Foundations

Status: **blocked on Phase 1; partial isolated foundations completed ahead of gate**

Goal: establish exact, deterministic foundations in isolated crates before any
product-path code changes.

### Target Ownership

```text
tools/ed25519-yao-generator/
  exact clear reference oracle
  deterministic circuit compiler and schedule generator
  test vectors and manifest emission

crates/ed25519-yao/
  validated protocol and circuit manifests
  embedded reviewed production artifacts after Phase 3B
  no clear joined evaluator or generator dependency
```

### TODO

- [x] Implement activation and export reference functions as distinct output
      types; seed output is impossible outside export.
- [x] Add RFC 8032, carry-heavy, clamp, reduction, output-equation, and
      noncanonical-scalar vectors.
- [x] Freeze `router_ab_ed25519_yao_v1`, activation circuit, and export circuit
      identifiers in the production crate.
- [x] Define validated digests and required circuit metrics without runtime
      backend or security-profile selectors.
- [ ] Implement a minimal fixed circuit IR and exact SHA-512 specialization.
- [ ] Implement 256-bit addition, clamp, reduction modulo `l`, `tau`
      aggregation, and both output equations.
- [ ] Emit canonical manifests, liveness schedules, deterministic digests, and
      real passive gate/table counts.
- [ ] Differential-test the clear evaluator against the Phase 1 oracle.
- [ ] Prove the production crate and Cloudflare bundles have no dependency on
      the generator, clear evaluator, or `ed25519-hss`.
- [ ] Run focused native tests, WASM compilation, boundary tests, and compiled
      constant-time review in proportion to each slice.

### Exit Gate

- [ ] Deterministic activation and export artifacts reproduce all vectors.
- [ ] Production manifest types reject zero, stale, unknown, or mixed digests.
- [ ] Circuit digests and counts reproduce across clean builds.
- [ ] Seed-bearing fields exist only in export outputs.
- [ ] No product route, SDK caller, or Cloudflare adapter changes in this phase.

## Phase 3A: Decide The Active Construction And Platform

Status: **blocked on Phase 1 and Phase 2 gate-count evidence; may run beside
the remaining isolated circuit and passive-core foundations once those inputs
exist**

Goal: approve an implementable active-security composition and deployment
profile before stream, preprocessing, integration, or release budgets harden
around passive assumptions.

`yaos-ab.md` Phase 6A owns the detailed candidate analysis and evidence. This
phase is the product-level approval gate.

### TODO

- [ ] Bound the construction survey to WRK17/KRRW18 authenticated garbling,
      SoftSpoken/KOS/Ferret-family OT choices, and Lindell-style or batched
      cut-and-choose.
- [ ] Disqualify dual execution for adversarial predicate leakage across retries
      involving long-lived derivation inputs.
- [ ] Freeze the active compiler, OT suite, input-provenance mechanism,
      randomized-output realization, active-output binding, garbling hash, and
      abort model.
- [ ] Choose and budget the reviewed implementation strategy: port and harden,
      compose narrow reviewed components, or implement in this repository.
- [ ] Project online/offline bytes, rounds, CPU, memory, preprocessing storage,
      request graph, lifecycle writes, and disposal semantics from real Phase 2
      counts and narrow microbenchmarks.
- [ ] Decide the Ed25519 platform rung: separate-account Workers, separate-
      account Containers, or independently administered native services.
- [ ] Update the normative deployment specification if the selected Ed25519
      profile differs from the initial separate-account Worker profile.
- [ ] Reissue the construction-specific Phase 9 latency, CPU, memory, payload,
      storage, and cost objectives.
- [ ] Freeze the epoch-floor authority, circuit rollout policy, admission
      mechanism, and ticket-burn budgets required by Phase 4.
- [ ] Obtain a signed construction decision record from the protocol,
      constant-time, deployment, performance, and independent reviewers.

### Kill Criteria

- [ ] Reject a candidate with unsupported composition, adversarial leakage, or
      a proof that excludes the required long-lived-input retry model.
- [ ] Reject an implementation path outside the approved effort and review
      budget.
- [ ] Move Ed25519 down the platform ladder when compiled constant-time review,
      resource projections, or the request/storage critical path fails the
      reissued budget.
- [ ] Stop Ed25519 Yao when the final independent-native profile fails the
      security, SLO, operational, effort, or review gate.

Succinct HSS and a passive Yao product path are absent from the fallback ladder.

### Exit Gate

- [ ] The signed Phase 3A/6A record freezes the construction, implementation
      strategy, platform, and assumption boundary.
- [ ] Reissued budgets account for all online and offline work and identify
      hard platform limits separately from product objectives.
- [ ] Streaming, one-use state, formal verification, and deployment can derive
      their exact requirements from the decision record.
- [ ] Every kill criterion has an evidence-backed disposition and no critical or
      high finding remains.

## Phase 3B: Build The Actively Secure Streaming Yao Core

Status: **blocked on Phase 2 artifacts and Phase 3A**

Goal: implement one role-local, actively secure fixed-circuit protocol in
`crates/ed25519-yao`.

### TODO

- [ ] Implement the exact Phase 3A active fixed-circuit compiler, malicious OT,
      provenance, randomized-output, and output-authentication composition.
- [ ] Define disjoint consuming Deriver A garbler and Deriver B evaluator state
      families.
- [ ] Implement fixed-size zeroizing labels, public unique gate tweaks, bounded
      schedule traversal, and incremental garbling/evaluation.
- [ ] Implement garbling correctness, evaluator-input consistency,
      selective-failure resistance, and authenticated private output.
- [ ] Bind role inputs to provisioned roots, epochs, request authorization, and
      the frozen stable derivation context.
- [ ] Define directional A-to-B and B-to-A frames with bounded canonical
      parsing and transcript authentication.
- [ ] Define distinct client activation, SigningWorker activation, and export-
      only seed output packages.
- [ ] Add corrupt-A, corrupt-B, malformed-OT, wrong-circuit, output-equivocation,
      replay, and abort tests.
- [ ] Measure exact online/offline payload, rounds, CPU, memory, and cold starts
      in the Phase 3A-selected environment, retaining rejected-profile evidence
      that activated any fallback tripwire.
- [ ] Delete losing passive or active-security experiment implementations before
      product integration.
- [ ] Obtain independent cryptographic review with no open critical or high
      finding.

### Exit Gate

- [ ] Router plus one malicious Deriver learns no forbidden peer or recipient
      value.
- [ ] A malicious Deriver produces a valid authenticated output or a detectable
      uniform abort.
- [ ] All Phase 1 vectors pass through separate role processes.
- [ ] The selected construction meets the reissued resource budgets on the
      approved platform.
- [ ] No passive protocol entrypoint is reachable from production code.

## Phase 4: Active Security And One-Use Role Protocol

Status: **blocked on Phase 3B**

Goal: give the selected active construction a crash-safe, one-use operational
lifecycle that meets the hardened one-malicious-Deriver claim.

### TODO

- [ ] Specify how Deriver A and Deriver B supply their private inputs without
      revealing selected labels or counterpart root contributions.
- [ ] Carry the Phase 3B reviewed OT and active-security suite into one-use
      preprocessing records without adding a second protocol.
- [ ] Implement input consistency, selective-failure resistance, authenticated
      internal values or labels, output authentication, and protocol-abort
      semantics.
- [ ] Bind preprocessing to account, wallet/key, request kind, role identities,
      recipient keys, root epoch, deployment epoch, protocol/circuit digest,
      authorization digest, expiry, and transcript nonce.
- [ ] Implement the Phase 3A-shaped
      `Generated -> Paired -> Available -> Reserved -> Activated ->
OutputPrepared -> OutputCommitted -> Consumed` lifecycle, with
      `Prepositioning` where approved and `Destroyed` from every nonterminal
      state.
- [ ] Burn uncertain material after crashes, timeouts, malformed peer responses,
      equivocation, or partial output release.
- [ ] Give A and B independent replay and consume records.
- [ ] Implement `EpochFloorAuthorityV1` as the independently administered,
      append-only signed release ledger with offline root keys, monotonic epochs,
      and cross-domain verification.
- [ ] Exclude epoch floors and revocation tombstones from role-state backups and
      reject every restored epoch below the signed floor.
- [ ] Enforce authenticated per-wallet, per-organization, per-tenant, and global
      generation, activation, and burn budgets before allocating a ticket.
- [ ] Attribute each burn's reason and CPU, storage, and preprocessing cost to
      the admitted principal; open a durable global circuit breaker when a
      budget is exceeded.
- [ ] Implement monotonic circuit rollout: stop old issuance, destroy old
      pre-activation tickets, bound the activated drain set, and forbid old
      digests for new activation or rollback.
- [ ] Add input-role swap, output-recipient swap, reflection, reordering, gap,
      duplicate, stale-epoch, cross-wallet, cross-operation, and mixed-circuit
      tests.
- [ ] Add concurrent-consume and crash-at-every-transition tests.
- [ ] Produce public share commitments `X_client` and `X_server` and verify
      `2 * X_client - X_server = A` before activation.
- [ ] Document that public commitment parity checks share consistency while the
      active-secure circuit supplies the derivation-correctness argument.
- [ ] Obtain independent review of the active-security composition and party
      views.

### Exit Gate

- [ ] Router plus one malicious Deriver learns no forbidden peer or recipient
      value.
- [ ] A malicious Deriver can cause at most a detectable abort or a valid output.
- [ ] Selective-failure and output-equivocation tests pass.
- [ ] One-use state cannot be replayed, cloned, rolled back, or consumed twice.
- [ ] Epoch rollback and circuit rollback cannot revive old ticket material.
- [ ] Ticket-burn budgets and the global circuit breaker contain adversarial
      disconnect cost.
- [ ] The approved security claim exactly matches the implemented composition.

## Phase 5: Strict Router A/B Protocol Integration

Status: **blocked on Phases 1 and 4**

Goal: give Ed25519 and ECDSA explicit, typed, strict Router lifecycles
without importing secret-processing code into Router.

### TODO

- [ ] Add `crates/router-ab-core/src/protocol/ed25519_yao.rs` with distinct
      registration, activation, recovery, refresh, and export request branches.
- [ ] Keep the existing strict ECDSA-HSS protocol as the ECDSA authority and add
      any missing bootstrap, export, recovery, refresh, pool-fill, or activation
      branches there.
- [ ] Define typed public request, Router admission, Deriver request, peer
      message, recipient output, activation receipt, and terminal result states.
- [ ] Add boundary parsers/builders that load the three Ed25519 Yao
      application-binding identifiers and immutable key-creation slot from
      authenticated domain records, enforce the frozen
      visible-ASCII/positive-`u32` grammar, and hash only typed facts.
- [ ] Make export fields impossible in registration, recovery, refresh, and
      activation branches.
- [ ] Make client and SigningWorker recipient packages distinct types.
- [ ] Make protocol/circuit/backend identifiers fixed by the request kind rather
      than caller-selected strings.
- [ ] Remove Ed25519 selection of `MpcThresholdPrfV1` from
      `protocol/public_request.rs` and every Ed25519 request builder.
- [ ] Retain threshold PRF for strict ECDSA derivation and remove it from every
      Ed25519 request, selector, vector, and fixture.
- [ ] Add a production adapter between `router-ab-core` and `ed25519-yao` without
      using `router-ab-dev` or a clear reconstruction helper.
- [ ] Add canonical encoding and cross-language vectors for every new request,
      transcript, peer message, output package, and receipt.
- [ ] Extend lifecycle, wire, output, error, and boundary parser tests.
- [ ] Add compile-time and source-guard tests rejecting joined state, mixed
      recipients, mixed protocols, optional identity, legacy service types, and
      broad object construction.
- [ ] Ensure normal Ed25519 and ECDSA signing remain Router-to-SigningWorker
      paths with zero Deriver calls after activation.
- [ ] Update `router-a-b-SPEC.md`, core README/specs, and route documentation to
      match the exact implemented branches.

### Exit Gate

- [ ] Core lifecycle switches are exhaustive.
- [ ] Invalid protocol, request, role, recipient, and epoch combinations fail at
      parsing or compilation.
- [ ] Router contract types contain no root, input-share, output-share, or clear
      HSS material.
- [ ] Ed25519 and ECDSA core vector suites pass.
- [ ] Normal signing traces prove zero Deriver calls.

## Phase 6: Selected Independent Runtime Profiles

Status: **blocked on Phase 3A and Phase 5 wire freeze**

Goal: implement the operational segregation required by the security claim.
ECDSA uses separate-account Cloudflare Workers. Ed25519 uses the single profile
approved in Phase 3A.

### TODO

- [ ] Add strict public Ed25519 registration, export, recovery, refresh, and
      activation routes to `crates/router-ab-cloudflare/src/paths.rs`.
- [ ] Complete strict ECDSA routes for every lifecycle identified in Phase 5.
- [ ] Run cryptographic role code only inside the selected Deriver A or Deriver
      B runtime adapters.
- [ ] Store secret role state only in the corresponding role-local persistence
      boundary; Cloudflare profiles use separate Durable Object namespaces.
- [ ] Implement authenticated, canonical, transcript-bound HTTPS transport
      between independent administrative domains.
- [ ] Sign peer envelopes over sender and recipient role, identities, method,
      path, body digest, transcript digest, sequence number, protocol/circuit
      version, root/key/deployment epochs, nonce, issue time, and expiry.
- [ ] Use distinct asymmetric keys for peer signing, role-envelope decryption,
      recipient output encryption, and deployment-manifest signing.
- [ ] Replace shared A/B internal bearer secrets with per-edge asymmetric
      authentication or reviewed mutually authenticated transport.
- [ ] Maintain independent atomic replay state at A and B.
- [ ] Return exact encrypted output-share package sets to Router and require
      Router to relay only opaque ciphertext to Client and SigningWorker.
- [ ] Require SigningWorker activation acknowledgement before a registration or
      refresh ceremony becomes complete.
- [ ] Add fail-closed startup validation for forbidden bindings, secrets, stores,
      endpoints, and duplicate role identities.
- [ ] Build role-specific artifacts and scan each final bundle for opposite-role
      secret owners and joined-state code.
- [ ] Provision separate Cloudflare accounts for ECDSA and for the preferred
      Ed25519 profile, including distinct CI, approvers, deploy tokens, Durable
      Objects, backups, logs, and audit exports.
- [ ] If Phase 3A selects Containers or native services for Ed25519, provision
      independent administrative domains and repeat dependency, constant-time,
      compiled-output, erasure, CPU-feature, placement, storage, network-cost,
      and incident-response review.
- [ ] Require each independent deployer to verify and approve the reviewed
      content-addressed artifact and protocol/circuit digest.
- [ ] Publish a signed deployment manifest and capability document.
- [ ] Make clients reject a downgrade from the required production profile.
- [ ] Add negative deployment tests proving Router cannot access either root
      store, A cannot access B resources, and B cannot access A resources.
- [ ] Enforce an isolate- or process-local ceremony guard before the first await
      or blocking operation, return a typed retryable busy result before ticket
      allocation, and combine it with durable wallet, organization, tenant, and
      global budgets.
- [ ] Benchmark the actual independent-domain topology, including cold starts,
      critical-path persistence transactions, p50/p95/p99 transition latency,
      admission rejection, and network latency.

### Exit Gate

- [ ] No principal or credential can administer both A and B.
- [ ] Signed cross-domain transport, replay, expiry, wrong-peer, and body-tamper
      tests pass.
- [ ] Router sees only public metadata, ciphertext, and receipts.
- [ ] Role-local crash/retry/equivocation tests pass in the selected persistence
      implementations.
- [ ] Independent-domain staging records the latency, memory, CPU, payload,
      storage, and cold-start evidence consumed by Phase 9; Phase 9 applies the
      reissued release budgets.

## Phase 7: Migrate Ed25519 Product Lifecycles

Status: **blocked on Phases 5 and 6**

Goal: move every Ed25519 product caller to the strict Rust Router A/B protocol.

### TODO

- [ ] Replace the browser evaluator/garbler lifecycle with client input
      derivation, A/B splitting, HPKE envelope construction, recipient-share
      opening, and result verification.
- [ ] Replace
      `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
      with one strict Router client lifecycle.
- [ ] Keep raw client roots, `y_client`, `tau_client`, output shares, and `d`
      inside Rust/WASM-owned secret types.
- [ ] Wire registration and SigningWorker activation through strict Router
      routes.
- [ ] Wire add-signer through the same strict derivation boundary.
- [ ] Wire passkey restore and email recovery through strict recovery grants and
      routes.
- [ ] Wire explicit export through a separate step-up grant and export branch.
- [ ] Wire server-share and activation refresh through strict refresh routes.
- [ ] Require the client to verify the public key after registration, recovery,
      refresh, and export.
- [ ] Require SigningWorker to combine only its A/B activation shares and reject
      client output packages.
- [ ] Make strict Router URL, deployment profile, protocol/circuit digest,
      SigningWorker identity, root epoch, and material binding required in
      persisted ready state.
- [ ] Bump persisted Ed25519 record versions and reject old ceremony/session
      shapes. Do not add restore compatibility.
- [ ] Replace TypeScript service calls in wallet registration, add-signer,
      recovery, export, and WebAuthn/email operations with scoped Router grant
      issuance and strict requests.
- [ ] Add E2E coverage for registration to normal sign, recovery to same key,
      export to standard import, refresh to same key, and add-signer.

### Exit Gate

- [ ] Repository traces show every Ed25519 derivation-time call enters strict
      Router A/B.
- [ ] No Ed25519 product caller invokes `ThresholdSigningService` or the old HSS
      WASM driver.
- [ ] Client and SigningWorker receive only their recipient-scoped shares.
- [ ] Standard export and public-key parity pass end to end.
- [ ] Normal signing remains Deriver-free.

## Phase 8: Complete ECDSA Strict Migration

Status: **blocked on Phases 5 and 6**

Goal: remove every remaining ECDSA dependency on the generic threshold service
and make strict Router A/B threshold-PRF derivation plus additive secp256k1
scalar shares the sole ECDSA architecture.

### TODO

- [ ] Inventory all ECDSA callers of `ThresholdSigningService`,
      `getThresholdSigningService`, `thresholdEcdsaOperations`,
      `thresholdEcdsaKeyInventory`, and threshold ECDSA route handlers.
- [ ] Map each caller to strict Router admission, Deriver A/B derivation,
      SigningWorker state, client WASM, or deletion.
- [ ] Freeze the stable ECDSA threshold-PRF context independently from ceremony
      transcripts and prove registration, export, recovery, and refresh identity
      parity with golden vectors.
- [ ] Authenticate each Deriver root-share commitment against its independent
      identity and epoch registry.
- [ ] Move ECDSA bootstrap and SigningWorker activation to strict ECDSA
      routes.
- [ ] Move ECDSA presignature pool creation and refill to strict Deriver and
      SigningWorker ownership.
- [ ] Move ECDSA normal signing to strict Router and SigningWorker exclusively;
      retain no generic service bridge.
- [ ] Move ECDSA export, recovery, refresh, and add-signer flows to explicit
      strict lifecycle branches.
- [ ] Replace TypeScript threshold-service authorization with scoped Router
      grants and typed strict requests.
- [ ] Move retained ECDSA stores to their actual owner: role-local Deriver,
      SigningWorker, Router lifecycle, or client worker.
- [ ] Remove ECDSA service acquisition from Cloudflare and Node router assembly.
- [ ] Remove ECDSA methods and types from generic auth-service ports.
- [ ] Update SDK ECDSA ready states so strict Router URL, Wallet Session grant,
      SigningWorker identity, key/root epochs, protocol version, and pool state
      are required.
- [ ] Add E2E coverage for ECDSA bootstrap to sign, pool hit, pool miss/refill,
      recovery, export, refresh, and add-signer.
- [ ] Add source guards proving normal ECDSA signing invokes zero Derivers after
      activation and no ECDSA path reaches the generic service.

### Exit Gate

- [ ] Every ECDSA public product flow enters a strict Router route.
- [ ] ECDSA derivation uses the frozen threshold PRF and additive scalar-share
      relation, with no `ed25519-yao` dependency.
- [ ] Every ECDSA secret is owned by Client, one Deriver, or SigningWorker as
      specified.
- [ ] No ECDSA caller references `ThresholdSigningService` or a successor
      centralized signing service.
- [ ] ECDSA public-key and signature vectors remain stable or an explicit key
      rotation has been recorded.
- [ ] Normal signing remains Deriver-free.

## Phase 9: Security, Constant-Time, And Performance Gates

Status: **blocked on integrated Phases 3B-8**

Goal: produce release evidence for the exact native, WASM, protocol, and
deployment artifacts that will ship.

### Constant-Time TODO

- [ ] Inventory role roots, `y`, `tau`, `d`, SHA-512 state, `a`, output shares,
      OT choices, labels, masks, preprocessing seeds,
      ECDSA shares, nonces, and presignatures as secrets.
- [ ] Require fixed circuit topology, loop counts, message counts, allocation
      sizes, and secret-payload lengths.
- [ ] Remove secret-dependent branches, iterator termination, indexes, table
      lookups, payload selection, division, and remainder.
- [ ] Use reviewed constant-time field/group operations and constant-time
      selection/equality.
- [ ] Verify the Phase 3A garbling hash as constant-time bitsliced/fixsliced AES
      in WASM or as the approved correlation-robust alternative; reject
      table-indexed software AES.
- [ ] Zeroize inputs, intermediates, masks, labels, OT state, RNG state,
      presignatures, and abandoned ceremonies.
- [ ] Keep secrets out of errors, logs, traces, metrics, panic payloads, debug
      formatting, and crash artifacts.
- [ ] Analyze isolated Rust secret kernels at `O0` and `O3` on x86_64 and arm64.
- [ ] Trace every analyzer finding to public or secret input and retain a triage
      report.
- [ ] Inspect every final optimized WASM after `wasm-opt` for secret-derived
      branches, indirect calls, loads, stores, division, and remainder.
- [ ] Inspect native assembly and enabled CPU features for every Container or VM
      cryptographic artifact selected in Phase 3A.
- [ ] Run fixed-versus-random timing tests for native kernels as supporting
      evidence.
- [ ] Repeat compiled-output review when Rust, LLVM, curve libraries, WASM
      tooling, or release flags change.

### Protocol And Adversarial TODO

- [ ] Run party-view tests for every supported corruption set.
- [ ] Fuzz every public, peer, persistence, and recipient-package parser.
- [ ] Test malformed/noncanonical/torsion points and invalid scalar encodings.
- [ ] Test replay, concurrent consume, rollback, crash recovery, expiry,
      reflection, reordering, gaps, wrong roles, wrong recipients, mixed epochs,
      mixed wallets, mixed protocols, and mixed circuit versions.
- [ ] Test epoch-floor rollback, old-circuit activation after the floor, bounded
      drain completion, backup restore, and stale-ticket non-revival.
- [ ] Test output equivocation and selective-failure attempts.
- [ ] Test local admission, durable budgets, typed busy rejection, global
      circuit breaking, and burn-cost containment under concurrent disconnects.
- [ ] Scan logs, diagnostics, persistence, browser messages, and crash records for
      secret material.
- [ ] Translation-validate the optimized circuit against the Phase 1 reference
      and pin IR digest plus gate count.
- [ ] Verify Ed25519 `2 * X_client - X_server = A` and standard export parity.
- [ ] Verify ECDSA public-key, signature, recovery-id, and presignature parity.
- [ ] Run full registration, recovery, export, refresh, activation, pool, and
      normal-signing E2E matrices for both protocols.

### Performance And Review TODO

- [ ] Record intended-product p50/p95, cold starts, memory, payloads, round trips,
      preprocessing throughput, storage, and pool exhaustion behavior.
- [ ] Record the exact critical-path persistence transaction/write graph plus
      p50/p95/p99 transition latency; identify safe A/B overlap and same-role
      coalescing.
- [ ] Record burns and attributed CPU, storage, and preprocessing cost by wallet,
      organization, tenant, global budget, reason, and attempted ceremony.
- [ ] Validate the signed Phase 3A SLO table. The earlier 250 ms p95, 500 ms
      p99, 150 ms combined CPU, 2.10 MiB passive payload, and 96 MiB Worker
      memory figures remain provisional planning objectives until that table is
      issued.
- [ ] Preserve historical HSS measurements as dated context; run no new HSS
      implementation or optimization experiment.
- [ ] Verify normal signing latency has not acquired Deriver work.
- [ ] Complete an independent cryptographic review of construction, parameters,
      amplification, active security, constant-time behavior, and implementation.
- [ ] Complete an independent deployment review of administrative separation, CI,
      credentials, storage, logs, backups, peer transport, and incident response.
- [ ] Close every critical and high finding. Give medium findings an explicit
      disposition, owner, and deadline.

### Exit Gate

- [ ] No unresolved secret-derived variable-time instruction, branch, or memory
      access remains.
- [ ] Native x86_64, native arm64, and shipped WASM evidence passes.
- [ ] All adversarial, vector, fuzz, lifecycle, and product tests pass.
- [ ] Product resource budgets pass on the selected independent-domain
      topologies.
- [ ] Both independent reviews approve legacy deletion and release progression.

## Phase 10: Hard Cutover And Legacy Deletion

Status: **blocked on Phases 7-9**

Goal: leave one strict production architecture and no compatibility path.

### Generic Service Deletion TODO

- [ ] Delete
      `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`.
- [ ] Delete `createThresholdSigningService.ts` and
      `createCloudflareDurableObjectThresholdSigningService.ts`.
- [ ] Delete `d1ThresholdSigningRuntime.ts` and remove it from Router/service
      assembly.
- [ ] Delete all `getThresholdSigningService` ports, providers, setters, getters,
      optional config, and exports.
- [ ] Move any still-current narrow helper into its real strict owner and delete
      the emptied generic module. Do not introduce an ECDSA-specific replacement
      service.
- [ ] Delete generic service stores and record shapes that exist only for the old
      ceremony architecture.

### Ed25519 Deletion TODO

- [ ] Delete Ed25519 HSS cases from
      `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`.
- [ ] Delete old prepare/respond/advance/finalize route definitions and constants.
- [ ] Delete
      `packages/sdk-server-ts/src/core/ThresholdService/ed25519HssWasm.ts`.
- [ ] Delete Ed25519 server-input combine code from `thresholdPrfWasm.ts` and
      `signingRootShareResolver.ts`.
- [ ] Delete legacy registration, add-signer, recovery, and export ceremony
      records and stores.
- [ ] Delete old browser evaluator/garbler lifecycle, worker messages, client
      driver state, and serialized ceremony state.
- [ ] Delete obsolete `near_signer` threshold-HSS exports and WASM feature
      branches.
- [ ] Delete simulator-only crate modules, binaries, benchmarks, fixtures, and
      formal claims after their real replacements land.
- [ ] Delete the `router-ab-dev` clear reconstruction adapter and tests.

### ECDSA Deletion TODO

- [ ] Delete legacy cases and service bridges from `thresholdEcdsa.ts` and
      related Node/Cloudflare route assembly.
- [ ] Delete old public `/threshold-ecdsa/*` route definitions, clients, and
      constants.
- [ ] Delete generic-service ECDSA authorization, key-inventory, pool-fill,
      recovery, export, and refresh helpers superseded by strict Router A/B.
- [ ] Delete old ECDSA session, presignature, and ceremony stores after strict
      owner migrations complete.
- [ ] Delete fixtures, mocks, snapshots, and tests that protect generic-service
      ECDSA behavior.

### Repository Cleanup TODO

- [ ] Reject and delete unfinished legacy Ed25519 and ECDSA ceremony records.
- [ ] Reject old persisted ready-session versions at the boundary and remove the
      parsers after development data cleanup.
- [ ] Delete stale environment variables, Durable Object bindings, migrations,
      deployment templates, and documentation for the generic service.
- [ ] Delete old route names, type aliases, feature flags, deprecated symbols,
      and fallback branches.
- [ ] Add repository source guards for old route literals, generic service
      symbols, joined HSS APIs, placeholder artifact types, simulator modules,
      and dev clear reconstruction.
- [ ] Add dependency guards proving production Router, Deriver A, Deriver B,
      SigningWorker, browser, and TypeScript bundles import only their allowed
      role surfaces.
- [ ] Scan final Worker and browser bundles for forbidden symbols and secret
      owners.
- [ ] Update Router A/B, Ed25519 HSS, ECDSA-HSS, deployment, recovery, export,
      local-dev, and optimization documentation.
- [ ] Delete tests and fixtures for obsolete behavior. Do not adapt them to
      preserve it.

### Exit Gate

- [ ] Repository search finds no `ThresholdSigningService` definition or caller.
- [ ] Repository search finds no active old Ed25519 or ECDSA threshold route.
- [ ] Repository search finds no production joined-state HSS API or simulator.
- [ ] One current Ed25519 protocol version and one current ECDSA protocol version
      remain.
- [ ] Full Rust, WASM, TypeScript, SDK, strict Router, E2E, and deployment suites
      pass.
- [ ] Obsolete secret records, Durable Objects, backups, and deployment bindings
      have documented destruction evidence.

Rollback means redeploying the same strict protocol artifact and restoring
role-local state from independently controlled backups. It never means
reactivating deleted code.

## Phase 11: Independent Production Evidence And Release

Status: **blocked on Phase 10**

Goal: prove the shipped system matches the strict two-operator architecture.

### TODO

- [ ] Deploy Router, Deriver A, Deriver B, and SigningWorker from the reviewed
      content-addressed artifacts.
- [ ] Have independent A and B operators verify and sign their deployment
      manifests.
- [ ] Capture account ids, deploy principals, artifact digests, peer-key
      fingerprints, envelope-key fingerprints, endpoint identities, protocol
      version, circuit digest, root epochs, and redacted access evidence.
- [ ] Run negative access probes proving A credentials cannot read or deploy B,
      and B credentials cannot read or deploy A.
- [ ] Run Ed25519 registration, activation, normal signing, recovery, export,
      refresh, and add-signer smoke tests.
- [ ] Run ECDSA bootstrap, activation, pool hit, pool refill, normal signing,
      recovery, export, refresh, and add-signer smoke tests.
- [ ] Verify Router, Deriver, SigningWorker, and client logs contain only allowed
      public metadata.
- [ ] Rehearse independent peer-key rotation, envelope-key rotation, deployment
      rollback, role revocation, incident freeze, backup restore, and audit-log
      correlation.
- [ ] Complete staging burn-in without replay, atomic-consume, memory-growth,
      identity-parity, or cross-role-access failures.
- [ ] Publish a signed release checklist and exact security capability claim.

### Exit Gate

- [ ] Production uses `router_ab_cloudflare_separate_accounts_v1`.
- [ ] Both independent operators approve the same reviewed protocol/circuit
      artifact.
- [ ] All product smoke and negative-access tests pass.
- [ ] No critical/high audit finding or security-claim mismatch remains.
- [ ] There is no legacy fallback in code, configuration, storage, deployment,
      or runbooks.

## Flow Completion Matrix

Every row must be green before Phase 10 deletion begins.

| Protocol | Flow           | Public owner | Secret-computation owners                   | Recipient                            | Required evidence                                       |
| -------- | -------------- | ------------ | ------------------------------------------- | ------------------------------------ | ------------------------------------------------------- |
| Ed25519  | Registration   | Router       | Deriver A + Deriver B                       | Client + SigningWorker               | Canonical vector, activation receipt, public-key parity |
| Ed25519  | Normal signing | Router       | Client + SigningWorker                      | Client                               | Zero Deriver calls, standard signature verification     |
| Ed25519  | Recovery       | Router       | Deriver A + Deriver B                       | Client + SigningWorker               | Same public key, fresh activation epoch                 |
| Ed25519  | Export         | Router       | Deriver A + Deriver B                       | Client only                          | Step-up, one-use auth, standard seed import parity      |
| Ed25519  | Refresh        | Router       | Deriver A + Deriver B                       | SigningWorker and client if required | Same public key, old epoch rejected                     |
| Ed25519  | Add signer     | Router       | Deriver A + Deriver B                       | New scoped recipient + SigningWorker | Identity and policy binding                             |
| ECDSA    | Bootstrap      | Router       | Deriver A + Deriver B                       | Client + SigningWorker               | Frozen public-key parity and activation receipt         |
| ECDSA    | Normal signing | Router       | Client + SigningWorker                      | Client                               | Zero Deriver calls, signature/recovery-id parity        |
| ECDSA    | Pool fill      | Router       | Client + strict role owners + SigningWorker | Client + SigningWorker               | One-use matched presignatures                           |
| ECDSA    | Recovery       | Router       | Deriver A + Deriver B                       | Client + SigningWorker               | Same public key, fresh activation epoch                 |
| ECDSA    | Export         | Router       | Deriver A + Deriver B                       | Client only                          | Step-up, one-use auth, public-key parity                |
| ECDSA    | Refresh        | Router       | Deriver A + Deriver B                       | SigningWorker and client if required | Same public key, old epoch rejected                     |
| ECDSA    | Add signer     | Router       | Deriver A + Deriver B                       | New scoped recipient + SigningWorker | Identity and policy binding                             |

## Source And Bundle Guards

Add guards as soon as the new owner exists; keep them after deletion.

| Boundary                    | Forbidden                                                                                                 |
| --------------------------- | --------------------------------------------------------------------------------------------------------- |
| Router                      | Deriver plaintext, root stores, secret HSS types, output-share opening, generic threshold service         |
| Deriver A                   | B root/store/decrypt key, joined values, SigningWorker private key, client output opening                 |
| Deriver B                   | A root/store/decrypt key, joined values, SigningWorker private key, client output opening                 |
| SigningWorker               | Deriver roots, client-output opening, Router authorization parsing, both-role executors                   |
| Browser TypeScript          | Raw roots, raw signing shares, `d`, `a`, HSS keys/tags, OT labels, presignature secrets                   |
| SDK/server TypeScript       | Threshold signing service, joined HSS execution, raw Ed25519/ECDSA shares                                 |
| Production dependency graph | `router-ab-dev`, simulator modules, placeholder artifact modules, clear reconstruction helpers            |
| Logs and diagnostics        | Any secret protocol payload, raw share, label, mask, nonce, seed, scalar, presignature, or decryption key |

Guards must inspect imports, public signatures, route registration, environment
bindings, final Worker bundles, browser bundles, and generated TypeScript/WASM
exports. String-only guards supplement structural type and dependency checks;
they do not replace them.

## Release Gates Summary

### Gate 0: Design Ready

- [x] Ed25519 Yao and ECDSA threshold-PRF/additive-share architecture and
      development identity policy are frozen.
- [x] Security claim, root policy, export behavior, and initial resource budgets
      are approved; executable party views remain a Phase 1 deliverable.
- [x] Independent cryptographic review is assigned as a mandatory Phase 3A/3B
      gate.

### Gate 1A: Construction Decision Ready

- [ ] The signed Phase 3A/Yao Phase 6A record freezes the active compiler, OT,
      provenance, randomized output, garbling hash, implementation strategy,
      platform, and assumption boundary.
- [ ] Named candidates, disqualifications, kill criteria, and the platform
      fallback ladder have evidence-backed dispositions.
- [ ] Construction-specific resource and SLO budgets are reissued before
      streaming, preprocessing, or protocol-level formal work starts.

### Gate 1B: Cryptographic Candidate Ready

- [ ] One reviewed active Yao suite implements malicious OT, garbler correctness,
      input provenance and consistency, selective-failure resistance, and
      authenticated private outputs.
- [ ] Standard, randomized, role-view, malformed-input, and export tests pass.
- [ ] Preliminary constant-time and resource budgets pass.

### Gate 2: Strict Integration Ready

- [ ] Every Ed25519 and ECDSA lifecycle uses typed strict Router A/B contracts.
- [ ] Recipient and role boundaries pass adversarial tests.
- [ ] No production API constructs joined state.

### Gate 3: Independent Deployment Ready

- [ ] Independent-domain access matrix, signed transport, replay, rotation,
      restore, and actual-topology performance evidence pass for the selected
      Ed25519 profile and the separate-account ECDSA profile.

### Gate 4: Legacy Deletion Complete

- [ ] `ThresholdSigningService`, both protocols' residual routes, joined HSS
      simulator, old stores, and compatibility paths are gone.

### Gate 5: Production Release

- [ ] Final native/WASM constant-time evidence passes.
- [ ] Independent cryptographic and deployment audits pass.
- [ ] Staging burn-in and every flow in the completion matrix pass.
- [ ] One production backend and one current protocol version per signature
      family remain.

## Recommended Execution Order

1. Use the closed Phase 0 decisions to complete the isolated Phase 1 oracle.
2. Build the isolated generator and gate-count foundations in Phase 2 while
   preparing the bounded Phase 3A decision evidence.
3. Close Phase 3A before construction-shaped streaming, preprocessing, or
   protocol-level formal work. Implement the chosen suite in Phase 3B.
4. Add the Phase 4 one-use lifecycle, epoch authority, circuit rollout,
   admission, and burn controls.
5. Prepare Phase 5 Router types and Phase 6 selected-profile infrastructure in
   parallel once the active transcript and wire contracts are stable.
6. Run Ed25519 Phase 7 and ECDSA Phase 8 in parallel after strict staging is
   available.
7. Run Phase 9 against the exact artifacts intended for cutover.
8. Perform Phase 10 as one hard deletion cut after both protocol flow matrices
   pass.
9. Release only through Phase 11 independent evidence.

## Completion Criteria

- [ ] Strict Router A/B is the only Ed25519 and ECDSA product
      architecture.
- [ ] Ed25519 exports the exact standard seed derived through
      `d -> SHA-512(d) -> clamp -> a`.
- [ ] `crates/ed25519-yao` implements one actively secure fixed-circuit
      construction with reviewed OT, role-local state, authenticated private
      outputs, and reproducible artifacts.
- [ ] ECDSA uses only strict Router A/B threshold-PRF derivation and additive
      secp256k1 scalar shares, with no Yao dependency.
- [ ] Router, Deriver A, Deriver B, SigningWorker, Client, storage, and logs obey
      the frozen party-view specification.
- [ ] Production A and B are controlled by independent administrators; ECDSA
      uses separate Cloudflare accounts and Ed25519 uses the Phase 3A-approved
      strict profile.
- [ ] Normal Ed25519 and ECDSA signing invoke no Deriver after activation.
- [ ] `ThresholdSigningService` and every replacement-shaped centralized
      service are absent.
- [ ] Old routes, stores, records, flags, aliases, mocks, fixtures, and fallback
      paths are deleted.
- [ ] Standard identity, export, recovery, refresh, signing, constant-time,
      adversarial, deployment, and audit gates pass.
- [ ] Active documentation states exactly the security claim supported by the
      shipped construction and deployment.

## Decision Log

| Date       | Decision                                                   | Reason                                                                                                                      |
| ---------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| 2026-07-10 | Strict Router A/B owns both Ed25519 and ECDSA              | One role-separated signing architecture; no generic service fallback                                                        |
| 2026-07-10 | Standard Ed25519 seed export is mandatory                  | Wallets must export/import through the canonical Ed25519 seed path                                                          |
| 2026-07-10 | Active Streaming Yao is the sole Ed25519 target            | It offers the highest-confidence path to the approved malicious-Deriver claim                                               |
| 2026-07-10 | Stop all succinct-HSS implementation and optimization work | Existing simulator and analytical measurements remain historical evidence only                                              |
| 2026-07-10 | ECDSA retains threshold PRF and additive scalar shares     | Its scalar lifecycle does not require the Ed25519 seed-to-scalar circuit                                                    |
| 2026-07-10 | Production requires independently administered Derivers    | ECDSA uses separate Cloudflare accounts; Ed25519 prefers Workers and retains the reviewed Containers/native fallback ladder |
| 2026-07-10 | Development cutover requires wallet reprovisioning         | One clean Yao-era stable context removes migration and compatibility paths                                                  |
| 2026-07-10 | No ECDSA-specific successor to `ThresholdSigningService`   | Existing strict Router A/B ECDSA components are the target owners                                                           |

## Phase Progress Record

Append one entry per meaningful phase result:

```text
Phase:
Date:
Commit:
Owner:
Scope completed:
Commands/tests:
Artifacts and digests:
Security evidence:
Performance evidence:
Deletion ledger:
Open blockers:
Gate decision: pass | fail | repeat
Decision rationale:
```

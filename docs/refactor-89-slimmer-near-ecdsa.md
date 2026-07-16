# Refactor 89: Slimmer Router A/B ECDSA Threshold Signer

Date created: July 15, 2026
Last reconciled with the implementation: July 16, 2026

Status: **active local cutover. Strict Router A/B derivation, authenticated
commitment verification, recipient-encrypted proof bundles, worker/artifact
separation, the purpose-built online Client, and the local intended-behaviour
checkpoint are complete. The fixed 2-of-2 presign rewrite remains isolated.
Production presigning and SigningWorker finalization still use the pinned
NEAR-backed `signer-core` implementation.**

Companion documents:

- [Streaming Yao and ECDSA client-boundary cleanup](./yaos-ab.md)
- [Router A/B solution refactor](./router-a-b-sol-refactor.md)
- [Router A/B specification](./router-a-b-SPEC.md)
- [Router A/B deployment](./router-a-b-deployment.md)

`yaos-ab.md` Phase 14B completed the active HSS rename, the narrow role-local
derivation client, the browser/server dependency boundaries, and local bundle
evidence. `router-a-b-sol-refactor.md` completed strict Router A/B lifecycle
migration and deletion of `ThresholdSigningService`. This plan now owns the
remaining purpose-built ECDSA presign cutover, persistent one-use pool,
pool-hit lazy-loading closure, bounded assurance, and deletion of the last
generic threshold-ECDSA implementation.

## July 16 Implementation Reconciliation

This section is the authoritative task tracker. The detailed phase sections
below remain as the construction record, security requirements, and historical
implementation ledger. Their unmarked bullets are supporting requirements;
only the checkboxes in **Remaining Local Phases** represent active work.

The current product path is intentionally described as a hybrid until the
cutover is complete:

- strict Router A/B ECDSA derivation and activation use the role-local
  purpose-built implementation;
- the browser online signature-share path uses `router-ab-ecdsa-online`;
- browser presigning and SigningWorker presigning/finalization still use
  `signer-core::threshold_ecdsa` and its pinned NEAR dependency; and
- `router-ab-ecdsa-presign`, `router-ab-ecdsa-online`, and
  `router-ab-ecdsa-pool` provide the fixed implementation and lifecycle
  contracts, but have not fully replaced those production call sites.

### Reconciled phase status

| Original phase | Current status | Reconciliation |
| ---: | --- | --- |
| 0 | Complete | Reproducible historical baseline, source freeze, vectors, and budgets recorded. |
| 1 | Complete | Deterministic metadata stripping and artifact evidence recorded. The historical mixed artifacts are deleted from the active tree. |
| 2 | Complete at the responsibility boundary | Derivation, presign, online, SigningWorker, and public EVM utility ownership are split. The integrated checkpoint uses one threshold-free `evm_crypto` leaf. A further `webauthn_p256`/`evm_transaction_codec` extraction is in progress and remains an optimization candidate until clean bundle and waterfall evidence chooses one final ownership layout. |
| 3 | Partial | The purpose-built online Client is integrated and below the 40,000-byte gzip ceiling. SigningWorker finalization, persistent one-use adapters, and a measured online-only pool-hit waterfall remain open. |
| 4 | Partial | The pinned dev/test oracle, vertical vectors, dependency exclusion, and construction drafts exist. The exhaustive normative specification, four-case semantic corpus, formal boundary, and independent Phase 4E review remain open. |
| 5 | Isolated implementation complete | The fixed cryptographic vertical slice and storage-independent pool lifecycle exist. Production promotion, authenticated pool-creation binding, and concrete storage adapters remain open. |
| 6 | Open | `router-ab-ecdsa-wire` has fixed typed values. The compact canonical presign transport codec, numeric registry, strict parser, byte corpus, and fuzz surface are not implemented. |
| 7 | Partial | Three role-specific Client workers, build manifests, generated types, and isolation guards are active. Production still uses the generic presign backend, and online-worker creation can create the presign worker. |
| 8 | Partial | Local derivation security evidence, intended-behaviour tests, bundle evidence, and source guards exist. Fixed-presign assurance and independent review remain open; deployed Cloudflare measurements are deferred. |
| 9 | Partial | Mixed Wasm/workers, active HSS terminology, generic service ownership, and obsolete derivation paths are deleted. `signer-core::threshold_ecdsa`, its production NEAR dependency edges, and generic participant/threshold APIs remain. |

### Completed product checkpoint

- [x] Strict Router A/B ECDSA derivation with authenticated root-share
      commitments and registry-bound DLEQ verification.
- [x] Recipient-encrypted ECDSA proof-bundle verification at the Client
      boundary.
- [x] Zero Deriver calls during normal signing, enforced by focused tests and
      source guards.
- [x] Separate derivation, presign, and online Client workers and Wasm package
      ownership.
- [x] Purpose-built online Client equations, parity vectors, consuming
      one-use types, and a 31,337-byte gzip artifact under the 40,000-byte
      ceiling.
- [x] Passkey and Email OTP registration, unlock, refresh, NEAR/Tempo/EVM
      signing, step-up, concurrent EVM-family signing, and Ed25519/ECDSA export
      intended-behaviour coverage.
- [x] Local bundle-isolation, source-boundary, dependency, and bounded
      security evidence for the currently integrated lifecycle.
- [x] Deletion of mixed `eth_signer`/`ecdsa_client_signer` packages, mixed
      workers, active ECDSA-HSS names, and `ThresholdSigningService`.

## Remaining Local Phases

These phases close this refactor locally. Cloudflare rollout, deployed
p50/p95/p99, production cost, rollback receipts, and multi-account operational
evidence belong to the deployment plans.

### Local Phase A: purpose-built production cutover

- [ ] Replace the browser presign wrapper's
      `signer_core::threshold_ecdsa::ThresholdEcdsaPresignSession` use with the
      fixed `router-ab-ecdsa-presign` Client role.
- [ ] Replace SigningWorker presigning with the fixed
      `router-ab-ecdsa-presign` SigningWorker role.
- [x] Replace SigningWorker finalization with `router-ab-ecdsa-online`.
- [ ] Remove runtime participant vectors, runtime role selection, threshold
      parameters, and generic state bags from every production boundary.
- [ ] Preserve exact public keys, addresses, low-`s` signatures, recovery IDs,
      signing budgets, recovery, and export behaviour through the cutover.

Exit: no production presign or finalization caller uses
`signer-core::threshold_ecdsa`.

### Local Phase B: one-use persistence and authority closure

- [x] Land the `router-ab-ecdsa-pool` storage-independent lifecycle contract
      with its exact identity bindings and absorbing tombstones.
- [ ] Implement the IndexedDB Client adapter with atomic compare-and-swap,
      transactional material deletion, destructive crash recovery, and no
      revival path.
- [ ] Implement the SigningWorker persistent adapter with the same monotonic
      reserve, commit, destroy, and tombstone semantics.
- [ ] Release a signature share or final signature only after the local
      committed-use mutation and material deletion succeed.
- [ ] Bind pool creation to the authenticated registry record and exact wallet
      public key before either party accepts usable presign material.
- [ ] Test concurrency, stale claims, timeout, cancellation, peer abort,
      ambiguous delivery, persistence failure, crash recovery, epoch
      retirement, and duplicate consume.

Exit: neither role can reuse or revive a pair half, including after failure or
uncertain delivery.

### Local Phase C: compact wire and true pool-hit lazy loading

- [ ] Freeze the purpose-built presign protocol identifier, numeric tag
      registry, bounded canonical encoding, transcript domains, message
      ceilings, and rejection rules.
- [ ] Implement strict one-pass decoders and deterministic byte vectors; add
      parser mutation and fuzz coverage.
- [ ] Remove the online worker's dependency on creating or loading the presign
      worker.
- [ ] Add a browser waterfall test proving a pool hit loads only online/public
      utility artifacts, downloads zero presign bytes, and makes zero Deriver
      calls.
- [ ] Keep presign loading restricted to explicit initial fill or observable
      refill policy.
- [ ] Finish or delete the in-progress public-utility leaf extraction from
      `evm_crypto` based on clean total-size and operation-waterfall evidence;
      leave one owner and one build path for each export.

Exit: normal pool-hit signing cannot fetch, instantiate, or message the
presign engine.

### Local Phase D: bounded fixed-backend assurance

- [ ] Complete the normative fixed construction, adversary model, upstream
      check inventory, assumption ledger, and exact oracle manifest.
- [ ] Complete the new/new and both mixed-role semantic replay modes plus the
      critical malformed-message, wrong-binding, replay, and abort corpus.
- [ ] Add compile-fail/API fixtures rejecting arbitrary participants,
      thresholds, roles, invalid lifecycle states, and reuse.
- [ ] Run native and Wasm constant-time analysis for the purpose-built presign
      and online kernels; record public-input findings and unresolved
      assumptions explicitly.
- [ ] Add targeted zeroization, secret-free logging/error, parser, and
      production-dependency checks.
- [ ] Obtain bounded independent cryptographic review before production
      promotion.

Exit: the selected construction and lifecycle claims have matching evidence;
remaining assumptions are explicit non-claims.

### Local Phase E: hard deletion and final readiness

- [ ] Delete `signer-core::threshold_ecdsa`, the `threshold-ecdsa` production
      feature closure, generic wrappers, and all production
      `threshold-signatures` dependency edges.
- [ ] Delete obsolete fixtures, tests, build aliases, generated assets,
      protocol names, and compatibility readers that exist only for the old
      presign backend.
- [ ] Add deleted-symbol and dependency guards for every removed owner.
- [ ] Run clean Rust/Wasm/SDK/server builds, focused crypto and persistence
      suites, bundle guards, and the complete passkey/Email OTP
      intended-behaviour checkpoint.
- [ ] Record the final local artifact digests, raw/gzip/Brotli sizes, local
      initialization and lifecycle timings, and a zero-old-caller report.
- [ ] Reconcile this document to complete and transfer only deployment work to
      the deployment plans.

Exit: the purpose-built fixed 2-of-2 implementation is the only local product
path and the repository is ready for the coordinated Cloudflare deployment
gate.

## Executive Decision

Build one purpose-built fixed 2-of-2 Router A/B ECDSA threshold signer. Execute
the work in three controlled steps:

1. strip release-only WebAssembly metadata;
2. split the mixed `eth_signer` artifact by responsibility and split
   presignature generation from online signing; and
3. replace the generic NEAR presign dependency with an exhaustive fixed Client
   plus SigningWorker state machine and a compact canonical codec.

The critical-path architectural target is the online/offline split. The small
`k256`-only online Client is integrated. Local Phase C closes the remaining
loader coupling so normal pool-hit signing cannot create or fetch the larger
presign artifact. Local Phase A gives the SigningWorker the equivalent
purpose-built presign/online separation.

The pinned NEAR implementation is the behavioral and cryptographic oracle.
Today it is also still reached by the presign Client and SigningWorker through
`signer-core::threshold_ecdsa`. Local Phases A and E remove that production
edge so `threshold-signatures` remains dev/test-only. The purpose-built
implementation reproduces the frozen equations, party views, state
transitions, transcripts, and outputs before the compact wire cutover.

The purpose-built implementation is the sole production target. The cutover
adds no runtime backend selector, old/new protocol negotiation, crate alias,
deprecated export, or fallback loader. Completion requires zero production
callers and release dependency edges to the NEAR oracle.

## Current Evidence

Phase 0 reproduced the last committed mixed artifacts from clean commit
`7e080b30f14a579d38b58c65fb058e1abac19c56` with the locked dependency graph.
The earlier 787 KiB estimate came from a different local artifact and is
superseded by this reproducible baseline:

| Artifact state | Raw bytes | gzip bytes | gzip KiB |
| --- | ---: | ---: | ---: |
| Optimized `eth_signer_bg.wasm` | 553,980 | 210,039 | 205.1 |
| Same binary after explicit metadata stripping | 553,854 | 209,954 | 205.0 |
| Immediate saving | 126 | 85 | 0.1 |
| Optimized `ecdsa_client_signer_bg.wasm` | 324,274 | 119,540 | 116.7 |
| Same binary after explicit metadata stripping | 324,148 | 119,457 | 116.7 |

The mixed signer's optimized WebAssembly sections are:

| Section | Bytes | Finding |
| --- | ---: | --- |
| Code payload | 508,129 | OT ECDSA and mixed utility exports share one reachable code image |
| Data payload | 38,427 | Protocol constants, messages, error text, and static data |
| Export payload | 1,188 | Mixed role and utility surface |
| Producers metadata | 126 | The only removable custom metadata in the optimized artifact |

The private pre-`wasm-opt` artifact retains a 142,689-byte name section for
symbol attribution. Its digest is mapped to the stripped shipped digest in the
machine evidence. The shipped artifact has no name, DWARF, producers,
source-map URL, or external-debug-info custom section.

The release configuration uses `opt-level = "z"`, LTO, one codegen unit,
`panic = "abort"`, and `wasm-opt`. Phase 1 added deterministic explicit
metadata stripping and assertions after binding generation.

The final Wasm contains reachable symbols for:

- NEAR OT-based ECDSA triple generation, random OT extension, multiplication,
  MtA, presigning, DLog/DLogEq proofs, and protocol actions;
- `frost-core` and `frost-secp256k1` types used by that ECDSA path;
- hundreds of `rmp-serde` encode/decode instantiations;
- `futures` protocol machinery;
- `k256`, `p256`, CBOR/COSE, EIP-1559, local secp256k1 signing, Router A/B
  derivation/bootstrap, and Wasm binding code.

The final Wasm contains zero identified `blstrs`, `blst`, `frost-ed25519`,
`curve25519-dalek`, NEAR EdDSA, or confidential-key-derivation symbols. Cargo
builds the monolithic pinned NEAR crate because it exposes no production
protocol/curve feature gates; LTO removes those unreachable algorithms from the
shipped image. Feature-gating those modules alone mainly improves build time.
Meaningful transfer-size savings require release stripping, artifact
decomposition, fixed two-party specialization, or a narrower message codec.

The historical mixed artifact exports threshold presigning and online signing
alongside EIP-1559, local secp256k1, P-256 WebAuthn, COSE, and ECDSA derivation
functions. Browser workers consequently instantiate the same large module for
different jobs. The ECDSA role-local worker also loads the separate
`ecdsa_client_signer` artifact, giving the historical ECDSA client path two Wasm
modules with 329,411 combined gzip bytes after explicit stripping, before
browser cache effects. Both historical packages are already deleted from the
active worktree; Phase 0/1 evidence rebuilds them only from the clean snapshot.

The complete measurements, digests, toolchain, source freeze, symbol groups,
runtime probes, and requirement coverage are recorded in
[`phase0-phase1-wasm-baseline-v1.json`](./evidence/refactor-89/phase0-phase1-wasm-baseline-v1.json).

## Rationale for a Purpose-Built Fixed 2-of-2 Library

The product protocol has one fixed shape: Client plus SigningWorker, threshold
two, secp256k1, OT-based presigning, and additive signature shares. It does not
need a public participant registry, arbitrary thresholds, DKG, resharing,
multiple curves, EdDSA, BLS, robust-ECDSA variants, or runtime role selection.

The pinned NEAR crate is designed as a general threshold-signature library. The
current reachable ECDSA path carries dynamic participant collections, generic
protocol actions, boxed state, futures execution, broad serde derivations, and
hundreds of MessagePack decoder instantiations. LTO already removes its unused
BLS and Ed25519 algorithms, so adding curve/module feature flags mostly reduces
build and review scope. Those flags do not remove the generic machinery reached
by OT presigning. Each two-party presign participant also executes both OT
sender and receiver substeps, so compiling a `client` or `server` feature does
not split the cryptographic code approximately in half.

The purpose-built library removes that mismatch directly:

- participant identities, roles, threshold, round counts, and message bounds
  become compile-time protocol constants;
- exhaustive role-specific enums replace generic futures and boxed protocol
  actions;
- fixed message types and a canonical bounded codec replace generic
  MessagePack decoding;
- browser and SigningWorker wrappers expose only their own role;
- online signing is isolated from OT presigning and uses a narrow `k256` core;
- invalid role, state, threshold, and participant combinations cannot be
  represented by the public API; and
- the final dependency and audit surface describes the protocol that is
  actually deployed.

NEAR remains valuable as an independently implemented oracle. Its pinned
revision supplies valid transcripts, invalid cases, proof/challenge values,
presignature outputs, signature shares, final signatures, and abort behavior.
Cross-executing each purpose-built role against the oracle catches arithmetic,
state-machine, transcript, and serialization drift before promotion. The
oracle remains outside every production dependency graph and release artifact.

This choice accepts local maintenance responsibility. Upstream changes are not
merged mechanically into production. The project watches the NEAR repository
and dependency advisories, classifies relevant correctness, security,
side-channel, and protocol changes, updates the pinned oracle through an
explicit change record, reruns the full differential corpus, and manually ports
applicable fixes into the purpose-built implementation. Any change to equations,
proof challenges, transcript encoding, randomness, or party views requires a
new review and versioned evidence.

The expected benefit is a materially smaller normal-signing artifact, a
smaller presign artifact, lower parse/compile/initialization cost, clearer role
isolation, and a review surface aligned with the exact Router A/B architecture.
The additional implementation and audit burden is deliberate and is reflected
in Phases 4 through 8.

## Goals

- Keep the reproducible historical mixed signer below 220,000 gzip bytes while
  the replacement remains isolated. Metadata stripping is a release-hygiene
  step; protocol decomposition owns the material size reduction.
- Keep normal pool-hit ECDSA signing's purpose-built client Wasm artifact below
  40,000 gzip bytes.
- Load OT presignature code only during explicit pool creation or refill.
- Remove all server-only bootstrap, finalization, and SigningWorker operations
  from browser dependency graphs.
- Remove P-256/COSE, EIP-1559 encoding, local private-key signing, and
  role-local derivation from the threshold-presign artifact.
- Preserve ECDSA public keys, Ethereum addresses, additive-share relations,
  signature bytes, recovery IDs, and export parity.
- Preserve strict Router A/B derivation and Deriver-free normal signing.
- Specialize the threshold signer to the actual fixed Client plus SigningWorker
  two-party protocol.
- Keep the pinned NEAR implementation exclusively in the oracle test harness;
  production dependency graphs contain no `threshold-signatures` package.
- Produce repeatable raw, gzip, Brotli, parse, compile, initialization, peak
  memory, first-operation, and steady-state measurements.
- Leave one current production artifact per responsibility and delete the mixed
  `eth_signer` package.

## Non-Goals

- Moving ECDSA derivation or signing to Yao.
- Changing the threshold-PRF derivation construction owned by strict Router
  A/B.
- Reintroducing ECDSA HSS terminology or a succinct-HSS implementation.
- Changing Ed25519 Yao artifacts.
- Moving normal signing through Deriver A or Deriver B.
- Creating an ECDSA-specific successor to `ThresholdSigningService`.
- Preserving development presignature pools across a protocol-wire cutover.
- Claiming malicious-security, constant-time, or formal-verification properties
  beyond the evidence actually completed in this refactor.

## Security and Lifecycle Invariants

All phases preserve these invariants:

1. ECDSA derivation remains strict Router A/B threshold PRF followed by
   additive secp256k1 scalar-share construction.
2. Deriver A and Deriver B never participate in normal signing after
   activation.
3. Client and SigningWorker are the only threshold-ECDSA signing parties.
4. The client never receives the SigningWorker's scalar share or presignature
   share. The SigningWorker never receives the client's scalar share or
   presignature share.
5. The Router authenticates, authorizes, binds, and transports protocol
   messages. It opens no scalar share or presignature share.
6. Every presignature is bound to one wallet, key identity, protocol version,
   participant role, root/key epoch, and one-use identifier.
7. Each party moves its local presignature through monotonic
   `available -> reserved -> committed_use -> destroyed` states. Entering
   `committed_use` atomically replaces the pool record with an irreversible
   tombstone and transfers the material once into the owned in-memory online
   state before secret-dependent output. A timeout, crash, rejection,
   concurrent request, or uncertain delivery after reservation destroys the
   pair. No design assumes a transaction spanning browser and SigningWorker
   storage.
8. Online rerandomization, Lagrange application, low-`s` normalization,
   recovery-ID selection, and signature verification preserve the frozen
   oracle equations. Exact bytes match when the same finalized public entropy
   is supplied; the joint-entropy flow is a reviewed strengthening.
9. Secret values remain outside logs, errors, metrics, filenames, cache keys,
   and diagnostic payloads.
10. Production release artifacts contain no Wasm debug names. Private release
    evidence retains an unstripped digest-matched artifact for diagnostics.
11. Each party proves or validates that its secret share matches the
    authenticated public-share commitment registered for the exact wallet,
    key, role, and epoch. The two registered commitments add to the wallet
    public key. A request-supplied key cannot replace registry state.
12. A usable Client/SigningWorker presignature pair has one shared canonical
    `R`, transcript digest, protocol identifier, key binding, and one-use
    identifier. Both role outputs must commit before either record enters the
    available pool.
13. Client and SigningWorker each commit an independent 32-byte contribution
    when a usable pair is created. Their ordered, verified reveals derive one
    fresh public rerandomization entropy value during committed use. Both role
    records bind the commitments, and the presignature remains single-use.
14. Every message and transcript challenge is domain-separated by protocol,
    codec, role, direction, round, session, wallet, key, root/key epoch, and
    deployment environment. Canonical bytes and exact ordering feed transcript
    hashes.
15. An exact retry may repeat only the previously committed bytes at the same
    sequence number. A changed duplicate, skipped round, reflection, reorder,
    or cross-session message aborts and burns the session.
16. All randomness used for OT, triples, proofs, presigning, identifiers, and
    rerandomization comes from an approved OS/platform CSPRNG with distinct
    domain-separated derivations. Deterministic RNG injection exists only in
    the oracle/test build and is absent from release dependency graphs.
17. Boundary parsers accept compressed non-identity SEC1 points, canonical
    fixed-width scalars, exact digests, bounded messages, and known tags only.
    Zero or out-of-range values are rejected wherever the equation requires a
    non-zero scalar.
18. The SigningWorker returns a signature only after verification against the
    exact authorized digest and registered public key. Low-`s` normalization
    and recovery-ID derivation are one coupled operation; normalization cannot
    leave a stale recovery bit.
19. Client-to-SigningWorker payloads are end-to-end authenticated and bound to
    the authorized session. Confidential payloads use recipient-scoped
    encryption. Router-visible metadata is minimal, public, and excluded from
    cryptographic authority.
20. Persistence, backup, retry, and crash recovery cannot move a committed,
    destroyed, expired, aborted, or consumed presignature into an available
    state. Epoch rollback invalidates all affected material.
21. Secret-bearing Rust types do not implement `Clone`, `Copy`, `Debug`, or
    general-purpose serialization unless a reviewed operation requires it.
    They have one owner, fixed-size storage, redacted errors, and explicit
    zeroization on every recoverable terminal path.
22. Oracle parity establishes behavioral equivalence only. The production
    security claim separately requires a frozen construction, assumption
    ledger, constant-time evidence, adversarial tests, and the bounded
    independent review defined by the approved assurance profile.

### Security review conclusion

The fixed-role API, narrow dependency graph, exact parsers, and exhaustive
state machines reduce product attack surface. The purpose-built cryptographic
rewrite introduces substantial implementation risk. Its highest-risk failure
mode is deleting a proof, consistency check, abort condition, or transcript
binding that appears generic in the upstream library and is essential to its
security argument.

Phase 4 therefore freezes an adversary model and a construction-level check
inventory before implementation. Every security-critical proof verification,
zero or canonicality check, peer-consistency check, transcript challenge,
randomness requirement, and abort rule reached by the fixed 2-of-2 path maps
to the purpose-built specification or to a reviewed fixed-setting
unreachability argument. Black-box vectors and successful signatures cannot
substitute for this inventory.

### Approved 80/20 assurance profile

The approved target is a behaviorally equivalent, fixed 2-of-2 distillation of
the pinned NEAR implementation. It preserves the product-used Client and
SigningWorker semantics and presents the narrow role-specific API defined in
this plan. It does not reproduce NEAR's generic participant-list, runtime-role,
or runtime-threshold API.

The release claim is limited to:

> The purpose-built fixed 2-of-2 implementation matches the pinned NEAR
> implementation for the exercised protocol equations, role-visible outputs,
> accepted and rejected inputs, state transitions, and abort behavior, under
> the recorded assumptions and preserved critical checks.

The required 80/20 evidence is:

1. A pinned NEAR commit, dependency/source digest, deterministic randomness
   harness, and immutable valid/invalid corpus.
2. A four-case oracle matrix: NEAR/NEAR source execution, new Client against a
   captured NEAR SigningWorker semantic trace, captured NEAR Client semantic
   trace against the new SigningWorker, and new/new. The two hybrid cases are
   deterministic role-replay tests; they make no wire-interoperability claim.
3. Parity for every fixed-path equation, party-visible value, output,
   rejection, timeout, abort, retry, and one-use transition. Production-wire
   tests use separately frozen canonical bytes. Oracle comparisons use
   normalized semantic events and exact NEAR bytes remain confined to the
   source-oracle fixtures.
4. A critical-check matrix covering OT consistency checks, unique OT/session
   identifiers, DLog/DLogEq verification, triple commitments, presign
   consistency equations, canonical scalar/point validation, fresh public
   rerandomization entropy, monotonic one-use state, final signature
   verification, low-`s`, and recovery ID.
5. Verus proofs for fixed participants/Lagrange coefficients, scalar domains,
   registered-share/public-key equality, online signature equations,
   low-`s`/recovery coupling, and monotonic reserve/commit/destroy states.
6. Positive downstream compile fixtures and generated Rust/Wasm/TypeScript API
   manifests freezing the approved product and fixed-role surfaces, plus
   compile-fail and TypeScript type fixtures proving the removed generic API
   and invalid cross-role/lifecycle calls cannot be constructed.
7. Focused malformed-message, replay, reflection, reorder, duplicate-use,
   rollback, crash, and differential fuzz tests.
8. Source plus exact release-native/Wasm constant-time inspection for the
   secret-bearing kernels and a release guard excluding oracle/test code.
9. A bounded independent review of the critical-check matrix, differential
   results, Verus obligations, and any deliberate semantic divergence.

These are promotion requirements rather than prerequisites for writing the
first isolated implementation slice. Development uses a time-boxed bootstrap
gate: pinned provenance, one deterministic happy path, the fixed equations and
adversary model, the critical security-check subset, and a narrow crate/API
skeleton. Exhaustive source scanning, complete invalid-vector coverage, exact
count guards, formal proofs, and signed review continue alongside the isolated
prototype. They must close before production promotion.

The provenance scaffold targets half a working day, and the complete bootstrap
has a one-working-day ceiling. If automation or guard construction reaches that
ceiling without finding a security-critical ambiguity, record the gap and
proceed with the manual inventory. Tooling is expanded when it directly
prevents a known class of omission or materially shortens repeated verification.

Deferred assurance work includes a new end-to-end UC proof, formal proofs of
the OT extension and discrete-log proof systems, exhaustive Lean privacy
models, adaptive-corruption proofs, generic `t`-of-`n` proofs, robustness, and
a broad audit of code outside the fixed product path. These remain explicit
non-claims. A future risk decision may promote selected items without changing
the narrow production API.

API parity is measured at two intentional boundaries:

| Boundary | Required parity | Explicit exclusion |
| --- | --- | --- |
| Product and SDK | Existing ECDSA registration, activation, pool management, signing, recovery, refresh, add-signer, and export behavior remains stable for callers | Old package names, mixed-role constructors, compatibility aliases, and deprecated feature flags |
| Fixed protocol roles | The new Client and SigningWorker APIs expose every input, output, error, abort, and lifecycle operation required by the exercised NEAR 2-of-2 path | NEAR's generic participant lists, runtime thresholds, runtime role selection, unrelated protocols, and server APIs in browser artifacts |

Rust compile-fail fixtures, generated Wasm/TypeScript declaration snapshots,
and TypeScript `@ts-expect-error` fixtures freeze these surfaces. The fixtures
also prove that arbitrary thresholds, swapped roles, incomplete identity or
session inputs, and invalid lifecycle transitions remain unconstructable. API
parity does not require preserving obsolete names or a generic facade.

## Security Footgun Register

| Footgun | Required prevention |
| --- | --- |
| Reusing a nonce, triple, or presignature after a retry or partial failure | Commit local use before output; treat uncertain delivery as consumed; make terminal states irreversible |
| Treating rerandomization as permission to reuse base material | Keep one-use semantics even with fresh rerandomization entropy |
| Accepting a public key or public-share commitment from the signing request | Resolve authenticated registry state by exact wallet/key/role/epoch and compare before protocol work |
| Allowing either role to reach `available` independently | Commit the matched pair through one transcript/pair receipt; expose neither half after a partial pool fill |
| Retrying a state-machine transition with changed bytes | Pin round, direction, sequence, and message digest; abort and burn on equivocation |
| Sharing mutable session state across concurrent requests | Consume typed states by value and permit one in-flight transition for each session/pair |
| Leaving deterministic RNG, oracle codecs, or test hooks in a release feature | Use dev-dependency/test-only owners and reject their symbols/features in final artifacts |
| Assuming `Drop` runs after a Wasm trap, `panic=abort`, or Worker termination | Minimize copies; zeroize recoverable exits; destroy the isolated Worker/Wasm memory on unrecoverable termination; document platform-owned copies |
| Moving secret bytes through JavaScript object spreads, strings, JSON, base64, logs, or structured-clone fan-out | Transfer one owned binary buffer into the exact Worker, overwrite controllable source views, and keep secret-bearing values out of generic SDK types |
| Using length checks as scalar/point validation | Enforce canonical scalar range, required non-zero checks, compressed SEC1 encoding, curve membership, and non-identity points |
| Computing recovery ID before low-`s` normalization | Normalize and derive/recover as one operation, then verify the final 65-byte result |
| Restoring a database snapshot that revives destroyed material | Keep monotonic tombstone evidence outside restorable pool records or reject restored records through epoch/generation state |
| Parsing attacker-controlled lengths before applying limits | Check protocol, round, tag, count, and byte ceilings before allocation or deserialization |
| Treating differential parity as a proof of malicious security or privacy | Limit parity claims to behavior and require explicit construction-level review and proof assumptions |
| Removing an upstream check because generic roles or thresholds disappeared | Maintain a construction-level check inventory and require reviewed justification for every removed check |
| Optimizing secret arithmetic through variable-time division, branches, comparisons, or table indexes | Inspect exact native and Wasm release code; trace findings to secret inputs; reject secret-dependent variable-time operations |

## Target Ownership

The recommended crate and artifact boundaries are:

| Owner | Responsibility | Forbidden dependencies or exports |
| --- | --- | --- |
| `router-ab-ecdsa-wire` | Fixed role, message, transcript, and presignature record types | Curve arithmetic, RNG, OT, Router services, storage adapters |
| `router-ab-ecdsa-online` | Client share computation, SigningWorker share/finalization, rerandomization, low-`s`, recovery ID, verification | `threshold-signatures`, OT, triples, `rmp-serde`, `futures`, derivation, P-256, EIP-1559 |
| `router-ab-ecdsa-presign` | Fixed two-party Client/SigningWorker presign protocol | `threshold-signatures`, `rmp-serde`, `futures`, generic threshold APIs, Deriver code, role-local derivation, EIP-1559, P-256, local full-key signing |
| `router-ab-ecdsa-derivation` | Phase 14B role-local threshold-PRF output handling and additive-share derivation | Threshold signing, OT, triples, SigningWorker APIs |
| `router_ab_ecdsa_derivation_client` Wasm | Client-only derivation, activation, refresh, recovery, and export cryptography | Presign/online signing engines, SigningWorker APIs, general EVM utilities |
| `router_ab_ecdsa_online_client` Wasm | Client-only online signature-share API | SigningWorker finalizer, server bootstrap, presign engine |
| `router_ab_ecdsa_presign_client` Wasm | Client-only pool-fill state machine | Online server APIs, derivation, general EVM utilities |
| `ecdsa-derivation-client.worker.ts` | Role-local derivation, activation, refresh, recovery, and export Client operations | Presign/online signing engines, SigningWorker code, general EVM utilities |
| `ecdsa-presign-client.worker.ts` | Client presign pool-fill sessions and one-use material creation | Derivation, online signing, SigningWorker code, general EVM utilities |
| `ecdsa-online-client.worker.ts` | Pool-hit Client signature-share computation | Derivation, presign engine, SigningWorker finalization, general EVM utilities |
| SigningWorker Rust/Worker owners | Server presign role, online finalization, pool persistence | Client state opening, Deriver shares, browser exports |
| `evm_crypto` Wasm | Threshold-free EIP-1559/public EVM codecs, local secp256k1 utilities, COSE parsing, and P-256 WebAuthn operations | Threshold signing, presign state, Deriver state, SigningWorker APIs |

`router-ab-ecdsa-online` may expose separate role-specific Rust modules, while
the public constructors accept exact role inputs. The browser wrapper exports
only the Client surface. The SigningWorker wrapper exports only the server
surface.

The generic runtime arguments still accepted by the active
`ThresholdEcdsaPresignSession` wrapper are a Local Phase A deletion target.
The purpose-built public API accepts no arbitrary participant vectors,
participant IDs, or thresholds and uses fixed role-specific constructors:

```text
ClientPresignSession::start(ClientPresignInput)
SigningWorkerPresignSession::start(SigningWorkerPresignInput)
compute_client_signature_share(OnlineClientInput)
finalize_signing_worker_signature(OnlineSigningWorkerInput)
```

Internal participant identifiers and the threshold are compile-time protocol
constants. Rust lifecycle state is represented by an exhaustive enum. The
TypeScript worker protocol mirrors it with discriminated request/result unions
and exhaustive switches. Raw Wasm values are parsed once at the wrapper
boundary into fixed-size arrays, canonical points, scalars, identifiers, and
typed lifecycle inputs.

## Target Runtime Flows

### Role-local derivation and activation

```text
Client -> strict Router A/B derivation -> Client additive share
SigningWorker <- recipient-encrypted strict Router A/B output <- Derivers
Client + SigningWorker -> public-key/share-consistency activation
```

This flow is owned by Phase 14B and does not load the presign engine unless the
activation policy immediately fills the pool.

### Presignature pool fill

```text
Client presign Wasm <-> Router transport <-> SigningWorker presign owner
                    fixed two-party OT/presign protocol
Client stores client presign handle/material
SigningWorker stores matching server material after the pair receipt commits
```

The presign Wasm is operation-lazy and may be preloaded during idle time. Pool
refill latency and bytes remain observable even when removed from the normal
signing critical path.

### Normal signing with a pool hit

```text
Client online Wasm -> client signature share
Router -> authenticated one-use transport
SigningWorker online kernel -> committed use, verification, final signature
```

The exact one-use ordering is:

1. The Client atomically moves its local pair from `available` to `reserved`
   and sends only the pair identifier plus authorized-use binding.
2. The SigningWorker validates authorization, registry/epoch state, and the
   matching pair, then atomically replaces its pool record with a tombstone,
   transfers the material into `committed_use`, and returns the committed
   public rerandomization entropy/use receipt.
3. The Client verifies the receipt and exact binding, moves its reserved half
   into `committed_use` with the same tombstone-and-transfer rule, and only
   then computes and releases its signature share.
4. The SigningWorker accepts that share once, combines, normalizes, derives the
   recovery ID, verifies the final signature, and returns it.
5. Any failure from step 1 onward leaves the local half unavailable. A bounded
   reconciliation request burns a peer half that has not observed the terminal
   outcome.

This flow loads no OT, triples, MessagePack, generic protocol driver, Deriver,
P-256, COSE, EIP-1559 encoder, or role-local derivation code unless the calling
product separately needs one of those leaf artifacts.

## ECDSA Presignature Pool and Background Refill

The current OT-based threshold-ECDSA construction requires one matched,
single-use presignature for every signature. A presignature is message
independent: Client and SigningWorker interact before the transaction digest is
known and obtain matching private shares of the public nonce commitment and
the `k`/`sigma` material. When a digest later arrives, the small online kernels
rerandomize that material, calculate both signature shares, combine them,
normalize low-`s`, select the recovery ID, and verify the final signature.

“Background refill” means running this required interactive presign protocol
proactively while the client runtime is open and the pool falls below a fixed
low-water mark. It does not eliminate presign computation, network rounds, or
cost. It moves message-independent work away from the user-visible signing
request and may amortize setup across a bounded batch.

The SigningWorker cannot create a usable matched presignature by itself. The
Client must participate in every refill that produces Client-owned material.
When the browser/client runtime is closed, full pool refill stops. Server-only
preparation may create explicitly classified local preprocessing inputs, but
those inputs are not counted as usable presignatures and cannot authorize or
complete a signature.

The intended lifecycle is:

1. Registration or activation synchronously creates the approved initial pool
   depth with both Client and SigningWorker present.
2. After a matched-pair receipt commits, each party atomically stores its local
   material under the same wallet, key, protocol, epoch, role, transcript, and
   one-use presignature identifier.
3. Signing reserves and commits one matching identifier locally on each side
   before secret-dependent output. Success, rejection, timeout, crash, or
   uncertain delivery destroys the in-memory material and never restores its
   pool tombstone to the available state.
4. When usable depth crosses the low-water mark, the active client schedules
   one bounded refill toward the high-water mark.
5. Cancellation, disconnect, timeout, mismatched commit, or failed verification
   destroys incomplete or unsafe material on both sides.
6. Expired, superseded, wrong-epoch, restored, or old-protocol material is
   destroyed and never returned to the usable pool.

A pool miss means no usable presignature exists. The product must follow one
typed policy: synchronously run presigning and make the caller wait, or return a
specific retryable pool-empty result. It cannot sign without presigning, reuse
old material, silently substitute another wallet/key/epoch, or let the server
manufacture the client's share.

Therefore the split changes latency placement rather than total cryptographic
work. Pool-hit signing uses the small online artifact and avoids OT on the
critical path. Registration, initial activation, refill, and pool-miss signing
still pay the presign cost, which remains part of the measured CPU, bandwidth,
memory, storage, burn-rate, and Cloudflare cost evidence.

## Initial Size and Runtime Budgets

Phase 0 records clean-build evidence and freezes the artifact budgets below.
Cloudflare latency, pool lifecycle, and complete SDK-distribution budgets stay
open until their corresponding measurements exist.

| Metric | Frozen gate |
| --- | ---: |
| Historical stripped mixed artifact | at most 220,000 gzip bytes |
| Historical role-local ECDSA client | at most 125,000 gzip bytes |
| Purpose-built online Client threshold signer | at most 40,000 gzip bytes |
| Purpose-built oracle-parity presign prototype | at most 512,000 gzip bytes |
| All unique ECDSA browser Wasm assets | hard ceiling 614,400 gzip bytes |
| Pool-hit normal signing presign download | 0 bytes |
| Pool-hit normal signing Deriver calls | 0 |
| Pool-hit signature/public-key behavior | exact frozen parity |

The total-distribution gate prevents a misleading split that duplicates
`k256`, binding glue, allocators, and serializers across enough files to make
the SDK larger overall. Operation-specific waterfall gates ensure a small
normal-sign path cannot hide an unexpectedly large registration, recovery,
refill, or export path.

No later optimization may regress the frozen p95/p99 online-sign latency, pool
throughput, peak memory, or correctness-error rate without an explicit revised
decision record.

## Historical Phase Map

This table records the original decomposition. Current status and execution
order are owned by **July 16 Implementation Reconciliation** and **Remaining
Local Phases** above.

| Phase | Name | Depends on | Exit result |
| ---: | --- | --- | --- |
| 0 | Freeze evidence, API, vectors, and budgets | None | Reproducible baseline and signed scope |
| 1 | Strip release metadata | Phase 0 artifact/source baseline | Mixed artifact at or below 220,000 gzip bytes |
| 2 | Split unrelated utility and role surfaces | Phase 1 | Role-correct leaf artifacts |
| 3 | Split offline presigning from online signing | Phase 2 | Small pool-hit signing path |
| 4 | Freeze purpose-built protocol and oracle boundary | Phase 0 for 4A; Phase 3 for 4E and exit | Reviewable specification and dev-only oracle |
| 5 | Build fixed 2-of-2 presign core | Phase 4 bootstrap for isolated prototype; Phase 4 exit for promotion | Purpose-built parity implementation |
| 6 | Add compact canonical codec and final slimming | Phase 5 | Production presign backend |
| 7 | Integrate SDK, Worker, and lazy loading | Phase 6 | One product path |
| 8 | Security, formal, and performance gates | Phase 7 | Release evidence |
| 9 | Hard cutover and deletion | Phase 8 | Mixed and obsolete paths deleted |

The original exit gates remain review inputs. They no longer imply that the
implementation must repeat already completed artifact, SDK, derivation, or
cleanup work. The active NEAR-backed production edges are confined to
presigning and SigningWorker finalization and are removed by Local Phases A
and E.

## Current Sequencing and Change Ownership

- Local Phase A owns the coordinated browser presign and SigningWorker
  presign/finalization cutover.
- Local Phase B owns both concrete persistence adapters and their
  authority-bound one-use lifecycle.
- Local Phase C owns the presign wire, loader decoupling, and pool-hit
  waterfall evidence.
- Local Phase D can proceed alongside A through C where it does not freeze a
  still-changing boundary. Independent approval follows the final integrated
  subject.
- Local Phase E deletes the generic backend and runs the final local readiness
  checkpoint. No compatibility bridge or runtime backend selector lands.

## Concurrent Development Boundary

The isolated-crypto boundary below explains how the purpose-built work was
developed. The repository has since crossed the Phase 7 integration boundary:
derivation and the online Client have production callers, while the fixed
presign core and pool model remain isolated until Local Phases A and B.

### Isolated crypto-track ownership

The crypto track may add and edit these new owners without touching SDK
integration:

```text
crates/router-ab-ecdsa-wire
crates/router-ab-ecdsa-online
crates/router-ab-ecdsa-presign
crates/router-ab-ecdsa-pool
crates/router-ab-ecdsa-near-oracle-tests
wasm/router_ab_ecdsa_online_client
wasm/router_ab_ecdsa_presign_client
wasm/router_ab_ecdsa_signing_worker
```

The old `wasm/eth_signer` package is deleted. The remaining frozen production
oracle edge is `crates/signer-core/src/threshold_ecdsa.rs`, used only by the
presign-specific Client and SigningWorker owners until Local Phase A. New work
must not add callers or broaden its API.

### Historical Phase 7 integration-reserved owners

This table is retained to explain the coordinated cutover surface. Several
listed old paths have already been deleted or renamed; the July 16
reconciliation is authoritative for current ownership.

Changes to these surfaces require coordination with concurrent SDK, Router,
auth, lifecycle, or build work:

| Area | Current owners requiring a coordinated cutover |
| --- | --- |
| Browser workers | `workerManager/workers/ecdsa-hss-client.worker.ts`, its planned derivation/presign/online replacements, `workerManager/workers/eth-signer.worker.ts`, `workerTypes.ts` |
| Browser EVM Wasm facade | `chains/evm/ethSignerWasm.ts`, EVM adapters, WebAuthn P-256 callers, Router A/B ECDSA pool/material owners |
| Runtime paths | `walletRuntimePaths/workers.ts`, `walletRuntimePaths/multichainWorkers.ts`, `build-paths.ts`, `build-paths.sh` |
| Browser build | `scripts/build/build-wasm.sh`, `build-sdk.sh`, `build-prod.sh`, asset manifests, bundle-size reports, Wasm smoke scripts |
| Server Wasm facade | `core/ThresholdService/ethSignerWasm.ts` and its public/internal exports |
| SigningWorker pool | `routerAb/ecdsaHssPoolFillLiveSession.ts`, pool-fill handlers, signing stores, durable session records |
| Router and recovery | ECDSA Router routes, Email OTP registration/recovery ECDSA helpers, protocol identifiers, request parsers |
| Console consumers | EVM relay/sponsorship imports of the server EVM signer facade |
| Tests and guards | distributed presign tests, Wasm-surface tests, worker guards, runtime-boundary guards, bundle reports, intended E2E |

Work that changes none of these integration-reserved owners may continue during
Phases 0 through 6. Work that changes one of them must either land before the
Phase 7 interface freeze or coordinate against the new exact bindings. Phase 7
does not start from a moving SDK integration surface.

### Historical merge checkpoint before SDK integration

The original Phase 7 design required one immutable integration bundle
containing:

- Rust API documentation for all four role/lifecycle owners;
- generated Client Wasm JavaScript and TypeScript declarations;
- server Rust/Worker API documentation;
- exact protocol, codec, and artifact digests;
- valid, invalid, and cross-role vectors;
- dependency and export allowlists;
- raw/gzip/Brotli and initialization measurements; and
- a passing purpose-built Client-to-SigningWorker local transcript.

The current integration satisfies the derivation, online Client, worker split,
and artifact-isolation portions. Local Phases A through C publish the remaining
fixed-presign, persistence, codec, and pool-hit evidence without adding a
runtime backend selector.

## Internal API Switchover Map

The public Seams SDK lifecycle remains registration, activation, signing,
recovery, refresh, add-signer, and export. Applications do not receive direct
presign-session objects. The internal Rust/Wasm and worker APIs intentionally
break at Phase 7.

| Current internal API | Purpose-built owner | Switchover rule |
| --- | --- | --- |
| `ThresholdEcdsaPresignSession::new(participant_ids, me, threshold, share, public_key)` | `ClientPresignSession::start(ClientPresignInput)` or `SigningWorkerPresignSession::start(SigningWorkerPresignInput)` | Remove runtime participants, role, and threshold from every caller |
| `stage`, `poll`, `message`, `start_presign`, `take_presignature_97` | Exhaustive role-specific transition/result APIs | Replace string stages and nullable bags with exact state/result variants |
| `threshold_ecdsa_compute_signature_share(...)` | `compute_client_signature_share(OnlineClientInput)` | Browser-only export with fixed Client semantics |
| `threshold_ecdsa_finalize_signature(...)` | `finalize_signing_worker_signature(OnlineSigningWorkerInput)` | SigningWorker-only export |
| `threshold_ecdsa_hss_role_local_relayer_bootstrap(...)` | Phase 14B `router-ab-ecdsa-derivation` owner | Remove from every threshold-signing artifact |
| EIP-1559, P-256/COSE, and local secp256k1 utilities formerly in `eth_signer` | Completed `evm_crypto` leaf | Preserve the high-level SDK facades while keeping the leaf free of threshold-signing dependencies |

The new Client and SigningWorker transition types use fixed-size byte arrays,
canonical points/scalars, role-bound session identifiers, exact protocol/key
epochs, and discriminated lifecycle states. Boundary parsers convert current
route, persistence, Worker, and Wasm values once. Core Rust and TypeScript logic
accepts no raw strings, partial records, optional identity fields, or broad
diagnostic objects that influence control flow.

Type-level fixtures must reject:

- arbitrary participant lists or thresholds;
- Client input passed to a SigningWorker transition or the reverse;
- messages delivered in the wrong round;
- missing wallet, key, protocol, role, epoch, or one-use identity;
- a consumed, expired, aborted, or incomplete presignature presented as usable;
  and
- broad object spreads or casts that bypass the exact state builders.

## Coordinated SDK and Deployment Switchover

Phase 7 performs the local/product integration. Phase 9 performs the hard
deployment and deletion. Both use one exact protocol version and one set of
content-addressed artifacts.

### Phase 7 local integration order

1. Add the generated purpose-built packages to the build without adding an old
   implementation selector.
2. Replace the browser Client presign import and worker state owner.
3. Replace the browser online signature-share import.
4. Replace the SigningWorker presign owner and durable state parser.
5. Replace the SigningWorker online finalizer.
6. Move EIP-1559, P-256/COSE, local secp256k1, and role-local derivation callers
   to their leaf artifacts.
7. Replace worker message unions, runtime paths, asset manifests, copy scripts,
   package declarations, smoke tests, and bundle reports.
8. Update Router envelopes and persistence records to the new exact protocol
   and codec identifiers.
9. Run registration/activation to initial pool fill, pool-hit signing, forced
   pool miss/refill, recovery, refresh, add-signer, and export locally.
10. Prove the old generated Wasm package has zero production callers before
    Phase 8 begins.

The old implementation may remain as test-oracle source during Phase 8. It is
absent from production loaders, manifests, and runtime branches.

### Persistence and protocol cutover

The purpose-built presign protocol uses a new exact protocol/wire identifier.
Old presignatures and in-flight presign sessions are incompatible and are never
translated.

- Stop old pool issuance before deployment.
- Count old usable, reserved, in-flight, expired, and abandoned records without
  logging secret material.
- Abort every old in-flight presign session.
- Destroy all old Client and SigningWorker presignature material, including
  reserved and abandoned records.
- Delete old pool/session record kinds and parsers after the destruction gate.
- Create the approved initial purpose-built pool with both Client and
  SigningWorker present.
- Accept only the new protocol identifier after admission reopens.

This presign cutover preserves the ECDSA additive shares, public key, Ethereum
address, and export result. It replaces one-time presign material only. A
combined Phase 14B key-domain cutover may separately require development and
staging wallet reprovisioning; that decision remains owned by Phase 14B and
must be recorded independently.

### Coordinated deployment order

1. Close new ECDSA presign and signing admission for the bounded maintenance
   window.
2. Verify the signed artifact manifest, protocol/codec digests, independent
   review receipt, size budgets, and account/environment targets.
3. Stage content-addressed Client assets without changing the active asset
   manifest.
4. Deploy the SigningWorker presign and online owners plus their new empty
   record stores.
5. Deploy the Router/request boundary that accepts only the new protocol and
   references the exact SigningWorker artifact digests.
6. Atomically publish the SDK/worker asset manifest pointing to the new Client
   Wasm files.
7. Run health checks and one controlled Client-to-SigningWorker initial pool
   fill plus verified signature.
8. Reopen admission.
9. Run the complete post-deploy smoke matrix and verify zero requests, imports,
   records, or metrics use old identifiers.
10. Purge obsolete static assets after the bounded stale-client window or
    immediately in development environments.

No deployment combines an old Client with a new SigningWorker or the reverse.
An already-open stale client receives one typed unsupported-protocol/reload
response at the request boundary. The server performs no message translation,
old-protocol execution, or fallback. Development and staging may require an
explicit reload or reprovision after the coordinated cutover.

### Rollback rule

Before the destructive Phase 9 deletion checkpoint, rollback deploys the
previous complete release set from signed artifacts. It never mixes old and
new Client, Router, SigningWorker, codec, or persistence owners. Before
admission has reopened, rollback may restore the previous set and refill its
empty one-time pool. After new protocol material has been issued, rollback
first closes admission and destroys all new presign sessions and material.

After Phase 9 deletes old schemas, readers, bindings, and static assets,
rollback to the old protocol is unavailable. Recovery uses a forward fix or
development/staging reprovisioning. No database record or protocol message is
converted between implementations.

## Cleanup and Deletion Ledger

Phase 9 closes every row. A row is complete only when replacement behavior
passes, obsolete source/assets/records are deleted, and a guard rejects their
return.

| Category | Replace or delete | Completion evidence |
| --- | --- | --- |
| Rust threshold core | Delete `signer-core::threshold_ecdsa`, generic participant/threshold helpers, boxed protocol driver, old errors and tests | Purpose-built native/Wasm tests and zero-import search |
| NEAR production dependency | Remove `threshold-signatures` from all normal/build features and release lock/dependency graphs | `cargo tree` and final symbol/bundle guards; dev/test oracle is the only allowed edge |
| Mixed Wasm crate | Delete `wasm/eth_signer`, generated `pkg`, old exports, declarations, package metadata, and smoke entrypoints | New leaf packages pass runtime smoke tests and old path is absent |
| Generated/static assets | Delete `eth_signer.wasm`, `eth_signer_bg.wasm`, old JS glue, declarations, maps, copied server assets, cache entries, and manifest keys | Clean SDK/server build and static-asset manifest check |
| Browser workers | Replace `ecdsa-hss-client.worker.ts` with `ecdsa-derivation-client.worker.ts`, `ecdsa-presign-client.worker.ts`, and `ecdsa-online-client.worker.ts`; delete mixed `eth-signer.worker.ts` responsibilities, old discriminants, loaders, session maps, and HSS material names | Role-specific workers pass guards, operation-waterfall checks, and intended E2E |
| Browser facade | Split `chains/evm/ethSignerWasm.ts`; remove threshold, P-256, derivation, and transaction-codec cross-loading | Operation waterfall and source-import guards |
| Server facade | Delete mixed `ThresholdService/ethSignerWasm.ts` ownership after callers move to exact leaves | Server package typecheck, Cloudflare smoke, zero-import search |
| Pool-fill runtime | Replace `ecdsaHssPoolFillLiveSession.ts`, handlers, string stages, dynamic participant inputs, and generic session maps | Fixed SigningWorker transition tests and durable-store smoke |
| Router/request types | Delete old HSS/generic route literals, protocol IDs, partial request shapes, and optional compatibility parsing | Exact boundary parser tests and source guards |
| Persistence | Destroy old pool/session material; delete old record kinds, codecs, indexes, cleanup jobs, fixtures, and migration-only readers | Record-count destruction receipt and zero old-record parser search |
| Build configuration | Replace `SOURCE_WASM_ETH_SIGNER`, `WASM_ETH_SIGNER_BG_WASM`, worker names, copy steps, expected-output checks, package exports, and bundle labels | Clean Wasm, SDK, server, and console builds |
| Tests and fixtures | Replace valid current lifecycle coverage; delete HSS/mixed-artifact snapshots, mocks, helpers, and obsolete behavior assertions | Focused suites plus intended E2E pass with deletion accounting |
| Formal verification | Move still-valid derivation proofs into `router-ab-ecdsa-derivation`; add separate presign/online proof inventories; delete old ECDSA-HSS paths, commands, fixtures, and claims | New exact-count formal/anti-drift commands pass and old owner names are absent |
| Documentation and operations | Remove active ECDSA-HSS/mixed-signer guidance; update pool, incident, rollback, deployment, size, and audit runbooks | Active-document source guard and review approval |
| Generic service | Delete remaining ECDSA callers, factories, getters, stores, and tests for `ThresholdSigningService` under the Router A/B plan | Repository search and strict Router A/B E2E |

Required deleted-symbol guards include:

```text
ThresholdEcdsaPresignSession
threshold_ecdsa_compute_signature_share
threshold_ecdsa_finalize_signature
threshold_ecdsa_hss_role_local_relayer_bootstrap
threshold-ecdsa-hss
ecdsa-hss-fv
ecdsa-hss-client.worker
eth_signer.wasm
eth_signer_bg.wasm
SOURCE_WASM_ETH_SIGNER
WASM_ETH_SIGNER_BG_WASM
```

Historical documents, explicit deleted-name guard fixtures, and the pinned
dev/test oracle harness may retain required strings through narrow allowlists.
Active production source, generated bindings, package metadata, manifests,
tests outside the oracle harness, examples, deployment configuration, and
current architecture documentation may not.

## Phase 0: Freeze Evidence, API, Vectors, and Budgets

Status: **complete; future-state implementation evidence is assigned to its
owning phases**

### Historical implementation ledger

- [x] Rebuild `wasm/eth_signer` and `wasm/ecdsa_client_signer` from a clean,
      locked checkout with the production toolchain.
- [x] Record Rust, LLVM, `wasm-bindgen`, `wasm-pack`, Binaryen, target, linker,
      and compression versions.
- [x] Record raw, gzip-9, Brotli, JS glue, TypeScript declarations, source-map,
      and package bytes for both historical packages.
- [x] Assign complete SDK distribution measurement to Phase 8 after the active
      asset graph and copy paths stabilize.
- [x] Record Wasm section sizes and a symbol-attribution report for NEAR
      threshold signatures, `rmp-serde`, `futures`, `k256`, `p256`, CBOR,
      EIP-1559, derivation, allocation, panic, and bindings.
- [x] Record local filesystem read, compile, instantiate, first lifecycle call,
      initial linear memory, and multi-instance process-memory proxies.
- [x] Assign real Cloudflare fetch, pool-fill, pool-hit, pool-miss, peak-memory,
      and retained-Worker measurements to Phase 8, where the integrated
      lifecycle exists.
- [x] Freeze the current pinned NEAR revision, source digest, license notice,
      dependency graph, and exact modules reached by the two-party OT path.
- [x] Freeze valid deterministic vectors for presign material, both online
      shares, final signature, low-`s`, recovery ID, and public-key verification.
- [x] Freeze the required invalid-input and abort behavior below; Phase 4 owns
      exhaustive oracle mapping and Phase 8 owns executable release coverage.
- [x] Freeze message-order, retry, abort, malformed-message, replay, duplicate,
      wrong-role, wrong-key, wrong-epoch, and one-use-consumption requirements.
- [x] Freeze initial pool depth, low/high-water marks, maximum depth, refill
      batch and concurrency, material expiry, burn policy, cancellation,
      disconnect recovery, and the typed pool-miss behavior.
- [x] Freeze wallet/user/tenant/global refill admission limits so
      background work cannot create an unbounded burn or storage path.
- [x] Add a differential harness that runs the frozen NEAR oracle and the
      purpose-built online implementation from the same deterministic valid
      transcript.
- [x] Assign complete invalid and reachable presign-state differential coverage
      to Phase 4C/4D and its release enforcement to Phase 8.
- [x] Freeze the new role-specific API shapes and remove arbitrary participant
      lists, participant IDs, and thresholds from the target interface.
- [x] Replace the initial size estimates with the measurement-backed artifact
      budget table above.
- [x] Add a machine-readable size report and CI budget input owned by this
      refactor rather than relying only on prose values.

### Frozen 80/20 Pool Policy

This baseline favors predictable pool-hit latency with a small bounded storage
and refill surface. Phase 8 may tune numeric values from measured evidence
through an explicit decision-record update.

| Policy | Frozen baseline |
| --- | --- |
| Initial usable pairs after activation | 2 |
| Low-water mark | 1 usable pair |
| High-water refill target | 2 usable pairs |
| Maximum usable plus in-flight pairs per wallet/key/epoch | 4 |
| Refill batch | 1 pair per session |
| Concurrent refill sessions | 1 per wallet, 2 per user, 16 per tenant, 64 per deployment |
| Material lifetime | 24 hours maximum; earlier key/activation-epoch retirement destroys it |
| Pool miss | typed retryable `pool_empty`; emit no signature share and allow one deduplicated active-client refill |
| Reservation outcome | success, rejection, timeout, cancellation, crash, or uncertain delivery permanently burns the pair |
| Partial pair | never usable; reconciliation destroys the peer half |
| Refill admission | reject above any wallet/user/tenant/deployment concurrency or wallet-depth bound |

Every refill consumes an authenticated wallet/key/epoch scope and a unique
pair identifier. Limits apply before expensive cryptographic work. Per-tenant
and deployment ceilings are configuration values capped by the frozen maxima;
they cannot be disabled.

### Frozen Invalid and Abort Policy

| Condition | Required result |
| --- | --- |
| Malformed or noncanonical point/scalar/proof/message | terminal typed rejection; destroy all session material |
| Wrong role, wallet, key, epoch, scope, transcript, pair, or protocol | terminal binding rejection before secret-dependent output; destroy material |
| Reordered, reflected, duplicated, or replayed message | terminal state/transcript rejection; tombstone the pair |
| Duplicate reserve or consume | `already_consumed`; no output and no transition back to available |
| Timeout, cancellation, disconnect, crash, or uncertain delivery | terminal local burn; reconciliation destroys the peer half |
| Pool empty | retryable `pool_empty`; no presign fallback inside the online signer |
| Persistence failure before or after output | fail closed and burn; ambiguous delivery never restores availability |

Phase 4 maps every reachable upstream check and target transition to this
policy. Phase 8 proves the implemented corpus, fault handling, and monotonic
one-use behavior before release.

### Phase 0 Checkpoint

- Clean source: commit `7e080b30f14a579d38b58c65fb058e1abac19c56`.
- Pinned NEAR threshold-signatures source: commit
  `db609be5021eb9d794f577601f422818fbdfe246`.
- Stripped historical mixed signer: 553,854 raw, 209,954 gzip-9, and
  168,965 Brotli-11 bytes.
- Stripped historical role-local client: 324,148 raw, 119,457 gzip-9, and
  93,176 Brotli-11 bytes.
- The largest attributed mixed-signer body groups are NEAR threshold code
  (152,816 bytes), MessagePack (86,754), allocation (44,878), secp256k1
  (38,354), and futures (23,656). Groups overlap and identify ownership rather
  than forming an additive partition.
- [`phase0-phase1-wasm-baseline-v1.json`](./evidence/refactor-89/phase0-phase1-wasm-baseline-v1.json)
  is the machine-readable authority. Its `phaseCoverage` object records full,
  partial, and missing requirements with confidence values.

### Exit Gate

- [x] A clean build reproduces the recorded baseline within an explained tool
      variance.
- [x] The current valid oracle corpus, source provenance, known corrected-OT
      divergence, and complete future corpus obligations are frozen.
- [x] The historical artifacts and purpose-built online Client have allowed
      dependency/export lists and machine-enforced size budgets.
- [x] Future purpose-built presign artifacts have frozen allowed/rejected
      dependency and export rules in the guard matrix.
- [x] Artifact size budgets and the pool policy are frozen; integrated latency,
      memory, throughput, cost, and complete-distribution gates are assigned to
      Phase 8.

## Phase 1: Strip Release Metadata

Status: **complete for the historical artifacts; reusable strip and budget
tooling retained for every replacement artifact**

### Historical implementation ledger

- [x] Add deterministic post-processing with explicit
      debug/producers stripping after binding generation.
- [x] Retain an unstripped private artifact, symbol report, and digest mapping
      for release diagnostics.
- [x] Assert that the shipped Wasm has no `name`, DWARF, `producers`, source-map
      URL, or external-debug-info section.
- [x] Verify the import/export sections, generated JS/TypeScript bindings, and
      runtime behavior remain unchanged.
- [x] Verify active SDK build/copy paths contain no reference to either deleted
      historical artifact. The evidence path does not restore them.
- [x] Add raw/gzip/Brotli evidence and machine-enforced gzip budgets.
- [x] Run Node and browser Worker lifecycle smoke tests against the optimized
      and explicitly stripped historical artifacts.
- [x] Run cold and warm local `workerd` Wasm smoke tests for both stripped
      artifacts.

### Phase 1 Checkpoint

- `scripts/refactor-89/wasm-metadata.mjs` inspects sections and surfaces,
  creates the stripped artifact, rejects forbidden metadata, and compares
  import/export surfaces.
- `scripts/refactor-89/check-wasm-budget.mjs` uses pinned external gzip-9 and
  Brotli-11 commands and enforces the machine evidence budgets.
- Explicit stripping removes the 126-byte producers section from each
  optimized artifact. It saves 85 gzip bytes from the mixed signer and 83 gzip
  bytes from the role-local client. Reachable code owns essentially all
  remaining size.
- Historical Node and browser lifecycle vectors pass after stripping. The
  local load benchmark records compile, instantiate, first-call, linear-memory,
  and process-memory proxies; it makes no Cloudflare network claim.
- Local `workerd` cold and warm requests load both generated bindings and their
  compiled Wasm modules from the exact frozen digests. Deployed-network startup
  remains a Phase 8 measurement gate.

### Exit Gate

- [x] Historical stripped `eth_signer_bg.wasm` is at most 220,000 gzip bytes
      under the pinned compressor; measured size is 209,954 bytes.
- [x] Historical import/export surfaces and the valid role-local lifecycle
      vectors pass after stripping.
- [x] Functional parity scope is the frozen historical valid lifecycle corpus;
      exhaustive target-state invalid coverage remains owned by Phase 4/8.
- [x] Symbolized private evidence can be matched to the exact stripped digest.

## Phase 2: Split Unrelated Utility and Role Surfaces

Status: **complete at the responsibility boundary; a further public-utility
leaf extraction is an unpromoted size/lazy-loading refinement**

### Historical implementation ledger

- [x] Create the leaf artifact map from the Target Ownership table.
- [x] Consolidate P-256 WebAuthn, COSE decoding, EIP-1559/public transaction
      codecs, and local secp256k1 utilities into the approved threshold-free
      `evm_crypto` leaf.
- Evaluate the in-progress `webauthn_p256` and `evm_transaction_codec`
      extraction using clean unique-byte and operation-waterfall evidence.
      Promote it only by deleting duplicate ownership and obsolete build paths
      in the same change.
- Keep Phase 14B role-local derivation/export in
      `router_ab_ecdsa_derivation_client`; remove its exports and dependencies
      from the threshold signer.
- Remove relayer bootstrap, SigningWorker finalization, server state, and
      server error shapes from every browser artifact.
- Remove client state-opening and client material types from every
      SigningWorker artifact.
- Make each package generate only its own JS glue, declarations, and Wasm
      file. Delete the mixed barrel after all callers move.
- Add `cargo tree`, Wasm symbol/import/export, generated declaration, and
      final bundle guards for every leaf.
- Measure individual and total bytes to catch duplicated curve, allocator,
      serializer, and binding code.

### Exit Gate

- The threshold-presign artifact contains no P-256, COSE, EIP-1559,
      role-local derivation, local full-key signing, or server-only browser
      exports.
- Passkey confirmation and ordinary EVM transaction encoding no longer
      fetch or instantiate the threshold-presign Wasm.
- Total unique browser assets remain inside the Phase 0 budget.

## Phase 3: Split Offline Presigning from Online Signing

Status: **partially complete; the purpose-built online Client is integrated.
SigningWorker finalization, persistent one-use adapters, and true pool-hit
artifact isolation remain in Local Phases A through C**

### Historical implementation ledger

- Create `router-ab-ecdsa-wire` with fixed canonical IDs, role tags,
      presignature handles, one-use bindings, and bounded message envelopes.
- Create `router-ab-ecdsa-online` using `k256` and the minimum hash/encoding
      dependencies required for the frozen online equations.
- Implement fixed Client signature-share computation from stored
      `big_r`, `k`, and `sigma` material.
- Implement fixed SigningWorker rerandomization, share combination,
      low-`s` normalization, recovery-ID selection, and final verification.
- Differentially compare both online roles with the current NEAR-backed
      wrapper over all frozen vectors and randomized valid cases.
- Add invalid point, zero/noncanonical scalar, malformed digest, mixed
      presignature, wrong participant, wrong key, wrong epoch, replay, and
      duplicate-consume tests.
- Prove by dependency guard that `router-ab-ecdsa-online` contains no
      `threshold-signatures`, `rmp-serde`, `futures`, OT, triples, DKG, or
      presign protocol driver.
- Create `router_ab_ecdsa_online_client` Wasm with the Client operation
      only.
- Keep the existing NEAR-backed mixed artifact frozen as an oracle baseline
      with zero new product integration. The new presign artifact begins in
      Phase 5 and has no `threshold-signatures` production dependency.
- Route pool-hit signing directly through the online artifacts.
- Load the presign artifact only for explicit pool creation/refill. Add
      idle preload as a performance policy rather than a static import.
- Preserve monotonic local reserve/commit/destroy semantics across client
      material handles, Router use tokens, and SigningWorker records. Add
      explicit reconciliation that destroys the peer half after partial or
      uncertain failure.

### Exit Gate

- The online Client artifact is at or below the frozen ceiling and passes
      exact signature-share parity.
- A pool-hit signing waterfall downloads zero presign-engine bytes and
      invokes zero Derivers.
- Pool-hit p95/p99 latency and peak memory meet the Phase 0 budgets.
- The new online and presign package graph contains no production edge to
      the pinned NEAR oracle.

## Phase 4: Freeze the Purpose-Built Protocol and Oracle Boundary

Status: **bootstrap and partial vertical evidence complete; exhaustive
specification, corpus, formal boundary, and independent Phase 4E approval
remain in Local Phase D**

Goal: turn the pinned NEAR implementation into a reproducible dev/test oracle
and write the complete fixed-path specification required to implement the
production 2-of-2 protocol without linking that crate.

### Source freeze and evidence standard

The oracle source is exactly:

| Item | Frozen value |
| --- | --- |
| Repository | `https://github.com/near/threshold-signatures` |
| Commit | `db609be5021eb9d794f577601f422818fbdfe246` |
| Git tree | `05f60d54971e2f1e417dab7191f0f5d02f82468c` |
| Product entry point | `crates/signer-core/src/threshold_ecdsa.rs` |
| Triple entry point | `generate_triple_many::<2>` |
| Presign entry point | `ot_based_ecdsa::presign` |
| Online behavior | local wrapper plus NEAR rerandomization equations |

Oracle generation uses a clean isolated `CARGO_HOME`. A global Cargo checkout
is never accepted as provenance because it may contain local modifications.
The corpus manifest records the commit, Git tree, clean-source archive digest,
Rust toolchain, target, features, lockfile digest, harness digest, and every
fixture digest.

The Phase 4 evidence map uses these classifications:

- `full_match`: exact fixed-path behavior is preserved.
- `specialized`: a generic condition becomes unrepresentable under fixed
  Client/SigningWorker types.
- `strengthened`: an upstream omission, ignored input, indefinite wait, or
  panic becomes a typed rejection and terminal burn.
- `excluded`: the path is unreachable in the fixed construction, with a
  reviewed argument and compile-time evidence.
- `ambiguous`: the upstream source or security reference does not establish a
  sufficient claim. Ambiguity blocks design approval.

Each mapping record includes the upstream source range, local wrapper range,
normalized behavior, classification, target owner, test/proof identifier,
assumption identifier, reviewer disposition, and confidence from `0.00` to
`1.00`. Mappings below `0.80` remain `ambiguous` and block Phase 5.

### Exact fixed construction

#### Parameters and key representation

- The group is secp256k1 of prime order `q`, with generator `G`.
- There are exactly two roles: `Client` and `SigningWorker`.
- The NEAR participant identifiers are frozen as Client `1` and SigningWorker
  `2`. NEAR maps these to interpolation coordinates `z_C = 2` and `z_S = 3`.
- The participant order is `[Client, SigningWorker]`, the reconstruction
  threshold is `t = 2`, and the Lagrange coefficients at zero are
  `lambda_C = 3` and `lambda_S = -2 mod q`.
- Router A/B derivation produces additive shares `d_C` and `d_S` satisfying
  `x = d_C + d_S mod q` and `X = xG`.
- Oracle-compatible Shamir evaluations are
  `x_C = d_C / lambda_C` and `x_S = d_S / lambda_S`. The production API owns
  additive role shares and performs this mapping internally. Generic
  participant identifiers, thresholds, and participant vectors do not exist in
  the production type system.
- `X`, the role, key epoch, activation epoch, normal-signing scope digest, and
  pool-pair identifier come from authenticated registry/session state. Signing
  requests cannot supply replacements for those values.

#### Construction stack

| Layer | Frozen construction and parameters | Source grounding | Mapping confidence |
| --- | --- | --- | ---: |
| Base random OT | Chou-Orlandi “Simplest OT” over secp256k1, 128 base OTs, private role-to-role messages | pinned `triples/batch_random_ot.rs`; upstream `triples.md` “Random Oblivious Transfer” | 1.00 |
| OT extension | KOS-style correlated/random OT extension with the amended consistency check, security parameter `128`, 768 requested OTs and 1024 internal padded rows per multiplication | pinned `correlated_ot_extension.rs` and `random_ot_extension.rs`; upstream `triples.md` “Extended Oblivious Transfer” | 0.90 pending review of the KOS22/SoftSpoken correction mapping |
| Multiplication | Two HMRT21-style MTA instances, each using `256 + 128 = 384` random OTs, composed into additive shares of a product | pinned `mta.rs` and `multiplication.rs`; upstream `triples.md` “MTA” and “Multiplication” | 0.95 |
| Committed triples | Cait-Sith committed triple generation, batched with `N = 2`, producing two threshold-two triples for one presignature | pinned `triples/generation.rs`; upstream `triples.md` “Triple Generation” | 1.00 |
| Presigning | Cait-Sith two-triple presigning, yielding `(R, k_i, sigma_i)` | pinned `presign.rs`; upstream `signing.md` “Presigning” | 1.00 |
| Rerandomization | NEAR/Groth-Shoup-style public rerandomization using HKDF-SHA3-256 and a non-zero `delta` | pinned `ecdsa/mod.rs` and `ot_based_ecdsa/mod.rs`; upstream `signing.md` “Rerandomization & Key Derivation” | 1.00 |
| Online signing | One private Client share, SigningWorker combination, low-`s`, final verification, and recoverable signature ID | local `threshold_ecdsa.rs:363-516`; pinned `sign.rs`; upstream `signing.md` “Signing” | 1.00 |

The construction/reference ledger pins the exact versions reviewed for these
claims: Chou-Orlandi [CO15](https://eprint.iacr.org/2015/267), the revised
[KOS15](https://eprint.iacr.org/2015/546) record and its stated proof repair,
Roy's [SoftSpokenOT](https://eprint.iacr.org/2022/192),
[HMRT21](https://eprint.iacr.org/2021/1373), and Groth-Shoup
[GS21](https://eprint.iacr.org/2021/1330). The ledger records page/theorem or
protocol identifiers and the pinned source ranges that instantiate each
reference. A repository document or function name alone is insufficient
evidence for a security claim.

The OT-extension row remains a Phase 4 blocker until an independent reviewer
confirms that the exact consistency check in the pinned code implements the
post-2022 repaired KOS construction claimed by the upstream documentation. A
behavioral oracle cannot close that proof-reference gap.

#### Triple generation equations

For each triple index `j in {0, 1}`, each role `i`:

1. Samples degree-one polynomials `e_i(X)` and `f_i(X)` and a zero-constant
   degree-one mask represented upstream by a degree-zero tail `l_i(X)`.
2. Commits to coefficient commitments `E_i = e_i G`, `F_i = f_i G`, and
   `L_i = l_i G` with an independent 32-byte hiding randomizer.
3. Computes `confirm_j = H(ordered commitments for j)`. The confirmation is
   the unique session identifier for the multiplication that produces the
   product-share constant.
4. Runs the fixed two-party OT/MTA multiplication on local constants
   `e_i(0)` and `f_i(0)`. The resulting role values `ell_i(0)` satisfy
   `sum_i ell_i(0) = (sum_i e_i(0))(sum_i f_i(0))` when all checks pass.
5. Reveals polynomial commitments and proves knowledge of `e_i(0)` and
   `f_i(0)` with DLog proofs bound to the triple transcript, role, and triple
   index.
6. Privately sends evaluations to the peer and reconstructs local shares
   `a_i = sum_j e_j(z_i)` and `b_i = sum_j f_j(z_i)`. It checks
   `a_i G = E(z_i)` and `b_i G = F(z_i)`.
7. Sets `C_i = e_i(0) F(0)` and proves the DLogEq relation
   `(e_i(0)G, e_i(0)F(0))`.
8. Proves knowledge of `ell_i(0)` for `hat_C_i = ell_i(0)G`, sets the masked
   sharing polynomial constant, and privately sends its evaluation to the peer.
9. Checks `C = L(0)` and `c_i G = L(z_i)`.
10. Returns `(a_i, b_i, c_i)` and `(A, B, C)` with
    `A = aG`, `B = bG`, and `C = cG = abG`.

Triple `0` is renamed `(k_i, d_i, e_i)` with public `(K, D, E)` and
`e = kd`. Triple `1` remains `(a_i, b_i, c_i)` with public `(A, B, C)` and
`c = ab`.

#### Presign equations

For each role `i`:

```text
k'_i     = lambda_i * k_i
e'_i     = lambda_i * e_i
a'_i     = lambda_i * a_i
b'_i     = lambda_i * b_i
x'_i     = lambda_i * x_i
e        = sum_i e'_i
alpha_i  = k'_i + a'_i
beta_i   = x'_i + b'_i
alpha    = sum_i alpha_i
beta     = sum_i beta_i
R        = e^-1 * D = k^-1 * G
sigma_i  = alpha * x_i - beta * a_i + c_i
```

Both roles require `eG = E`, `alpha G = K + A`, and `beta G = X + B` before
returning a presignature. The reconstructed value satisfies
`sigma = sum_i lambda_i sigma_i = kx`. Each output `(R, k_i, sigma_i)` is
bound to one scope, key epoch, activation epoch, pair identifier, triple pair,
and protocol version. It is consumed once.

#### Public rerandomization and online signing

The oracle derives `delta` using HKDF-SHA3-256 with the pinned 32-byte NEAR
salt, 32-byte public entropy as input key material, and this exact info order:

```text
salt = 328a47c2b8794445255c1647608df5db85c68bb0e7170abec534df2764a45831
```

```text
retry_counter_u8 || 0x01 || X_compressed33 || tweak_scalar32 ||
digest32 || R_compressed33 || client_id_u32_le || signing_worker_id_u32_le
```

The initial retry counter is zero. HKDF output is parsed as a canonical scalar;
zero or out-of-range output increments the counter and retries. Production uses
the same equation with `tweak = 0`:

```text
R'       = delta * R
k'_i     = k_i / delta
sigma'_i = sigma_i / delta
r        = x_coordinate(R') mod q
h        = digest32 reduced mod q
s_i      = h * lambda_i * k'_i + r * lambda_i * sigma'_i
s        = s_C + s_S
```

The SigningWorker conditionally replaces high `s` with `-s`, rejects zero `r`
or `s`, verifies `(r, s)` against the exact `digest32` and registered `X`, and
derives the recovery ID against that same key and digest. It returns
`r32 || s32 || recovery_id_u8` only after all checks succeed.

The target adversary model requires entropy that a malicious single role cannot
choose after learning the peer contribution. Phase 4 therefore freezes one
deliberate internal hardening divergence: each role commits to an independent
32-byte entropy contribution during pair creation; the SigningWorker reveal is
piggybacked on prepare and the Client reveal is piggybacked on finalize.
`pair_id32` is a public uniformly random 32-byte identifier whose reuse is
rejected against live records and tombstones. The exact bindings are:

```text
pair_context_digest32 = SHA-256(
    "seams/router-ab-ecdsa-presign-pair/v1\0" ||
    normal_signing_scope_digest32 || pair_id32
)

client_commitment32 = SHA-256(
    "seams/router-ab-ecdsa-entropy-commit/v1\0" ||
    pair_context_digest32 || 0x01 || client_seed32
)

signing_worker_commitment32 = SHA-256(
    "seams/router-ab-ecdsa-entropy-commit/v1\0" ||
    pair_context_digest32 || 0x02 || signing_worker_seed32
)

entropy32 = SHA-256(
    "seams/router-ab-ecdsa-rerandomization-entropy/v1\0" ||
    pair_context_digest32 || client_seed32 || signing_worker_seed32
)
```

The normal-signing scope digest already commits the wallet/key identity,
protocol identity, key epoch, activation epoch, and deployment scope. Both
commitments are stored in both pair receipts and verified before any signature
share is released. This preserves the high-level SDK surface and the NEAR
rerandomization input while providing unpredictability when either role is
honest.

### Exact party views and outputs

| Role and phase | Private view | Authenticated public/peer view | Owned output |
| --- | --- | --- | --- |
| Client triple generation | additive key share, mapped oracle share, polynomials, OT choices/seeds, MTA masks, proof nonces, commitment randomizers | fixed context, peer commitments/proofs/evaluations, exact round metadata | two Client triple shares plus common public triple commitments |
| SigningWorker triple generation | additive key share, mapped oracle share, polynomials, OT choices/seeds, MTA masks, proof nonces, commitment randomizers | fixed context, peer commitments/proofs/evaluations, exact round metadata | two SigningWorker triple shares plus common public triple commitments |
| Client presign | Client key/triple shares and local entropy seed | common public key, public triples, peer `e`, `alpha`, `beta`, peer entropy commitment | Client `(R, k_C, sigma_C)` and matched-pair receipt |
| SigningWorker presign | SigningWorker key/triple shares and local entropy seed | common public key, public triples, peer `e`, `alpha`, `beta`, peer entropy commitment | SigningWorker `(R, k_S, sigma_S)` and matched-pair receipt |
| Client online | Client presign shares and unrevealed entropy seed | authorized digest, scope/pair receipt, SigningWorker entropy reveal, public `R'` | one `s_C` plus Client entropy reveal; local pair becomes destroyed |
| SigningWorker online | SigningWorker presign shares and unrevealed entropy seed | authorized digest, scope/pair receipt, Client entropy reveal and `s_C` | verified 65-byte signature; server pair becomes destroyed |

The Client never receives the SigningWorker's `k_S`, `sigma_S`, or signature
share. The SigningWorker never receives the Client's additive key share,
`k_C`, or `sigma_C`. The online `s_C` is released only after committed use and
is bound to one digest, rerandomization value, and pair.

### Exact adversary model

The release claim targets malicious security with abort for a static corruption
of at most one signing role for the full lifetime of one activated wallet key:

- A corrupted Client or SigningWorker may choose inputs and randomness,
  equivocate, send malformed messages, replay, reorder, omit, delay, or abort.
- Both roles colluding can reconstruct the key. This is outside the claim.
- The adversary controls the Router and network for delivery, duplication,
  ordering, delay, replay, and traffic observation. End-to-end authenticated
  encryption prevents undetected modification, sender forgery, and disclosure
  of private protocol messages.
- A malicious role can deny service and force pair destruction. Fairness,
  guaranteed output delivery, robustness, identifiable abort, and blame are
  outside the claim.
- Adaptive corruption across both roles, mobile corruption that reaches
  different roles across epochs, compromise of an honest endpoint's memory or
  runtime, cryptographic side channels outside the reviewed kernels, platform
  snapshots, and rollback beyond the authenticated epoch/tombstone boundary
  are outside the claim.
- Derivers are absent from presigning and normal signing. Their only relevant
  output is the already-activated additive share and authenticated public-share
  registry state.
- Privacy and unforgeability rely on at least one honest role, the exact OT/MTA
  composition accepted by design review, fresh independent randomness,
  joint public rerandomization entropy, monotonic one-use storage, and the
  formal assumption ledger below.

Every local or peer-detected error causes a terminal session abort. Both local
triple/presign halves transition to `destroyed`; uncertain delivery also burns
the pair. An authenticated abort receipt triggers peer reconciliation. Timeout
and crash recovery cannot return any reserved or committed material to
`available`.

### Transcript and message freeze

Phase 4 freezes two transcript profiles:

1. `near-oracle-v1` reproduces the pinned transcript byte for byte. It uses the
   upstream triple label, group name, sorted MessagePack participant list,
   big-endian `u64` threshold, MessagePack vector of two confirmations, and
   the upstream `dlog0`, `dlog1`, `dlogeq0`, and `dlog2` forks with four-byte
   little-endian participant identifiers. This profile exists only in the
   dev/test oracle and role-trace replay harness.
2. `router-ab-ecdsa-presign-v1` is the sole production profile. Transcript
   encoding is independent from transport encoding. Each field is encoded as
   `tag_u16_be || length_u32_be || value`, with strictly increasing tags,
   fixed-width integers, 32-byte big-endian canonical scalars, compressed
   SEC1 points, and exact role bytes. Duplicate, missing, unknown, oversized,
   or out-of-order fields abort.

The production root transcript absorbs, in order:

```text
domain = "seams/router-ab-ecdsa-presign/v1"
suite = "secp256k1+sha256+sha3-256"
normal_signing_scope_digest32
presign_pair_context_digest32
roles = [(client, z=2), (signing_worker, z=3)]
threshold = 2
triple_count = 2
```

`presign_pair_context_digest32` uses the exact formula in the joint-entropy
section. Each triple proof fork adds the proof kind, triple index, prover role,
statement, and proof commitment. Each OT/MTA session adds the pair-context
digest, triple index, subprotocol identifier, direction, and unique session
number. No setup seed or OT session identifier is reused.

Every transport message has one authenticated header containing protocol
version, scope digest, pair-context digest, phase, subprotocol, triple index,
round, sender role, receiver role, sequence number, payload length, and payload
digest. The parser validates the complete header before allocating or decoding
the payload. Unknown senders, wrong roles, wrong contexts, duplicates,
reflection, stale rounds, trailing bytes, and unexpected messages cause a
controlled terminal abort.

`transcript-v1.md` is the numeric registry for the production profile. It must
assign every transcript tag, transport message type, phase, subprotocol, proof
kind, role byte, abort code, field order, scalar/point encoding, payload bound,
and complete-message bound. Reserved values are listed explicitly and are
rejected on receipt. The registry includes one canonical byte vector for every
message and proof/KDF transcript. Phase 4 cannot complete with symbolic tags,
provisional numbers, implementation-selected ordering, or an unspecified
length ceiling.

### Randomness inventory

| Random value | Size/domain | Generator | Uniqueness and binding requirement |
| --- | --- | --- | --- |
| `e_i`, `f_i`, `l_i` coefficients | secp256k1 scalars | role-local CSPRNG | fresh per role and triple index |
| Commitment randomizers | 32 bytes | role-local CSPRNG | fresh per commitment; never reused across triples |
| DLog/DLogEq nonces | non-zero secp256k1 scalars | role-local CSPRNG | fresh per proof kind, role, triple, and transcript |
| Base-OT sender `y` and receiver `x` values | secp256k1 scalars | role-local CSPRNG | fresh per OT session and triple |
| Base-OT receiver choice `Delta` | 128 bits | role-local CSPRNG | fresh per OT session and direction |
| Random-OT consistency seed/choices | 32 bytes plus padded choice vector | role-local CSPRNG | fresh per OT-extension session; session ID unique |
| MTA masks and transcript seeds | 384 scalars per direction plus 32-byte seeds | role-local CSPRNG | fresh per multiplication and direction |
| Pair identifier | 32 bytes | role-local CSPRNG at pair creation | globally unique within scope; reuse against a live record or tombstone aborts |
| Entropy contributions | 32 bytes per role | role-local CSPRNG | committed during pair creation; revealed once during committed use |
| Rerandomization `delta` | non-zero secp256k1 scalar | deterministic HKDF-SHA3-256 from finalized public entropy and frozen arguments | one derivation per pair/digest; at most 256 canonical-scalar attempts |
| Transport keys and nonces | strict Router A/B channel-suite domains | authenticated channel owner | exact suite is cited by `A-CHANNEL`; nonce uniqueness is bound to key, pair context, direction, and sequence |
| Deterministic oracle coins | named byte streams | test-only deterministic provider | derived from fixture ID, role, phase, subprotocol, triple index, and draw index |

The deterministic provider is accepted only by the oracle and test builds. A
release dependency/symbol guard proves it is unreachable from production.

### Upstream security-check and abort matrix

`upstream-check-inventory.md` contains one row for every `Err`, failed proof,
failed equality, deserialization failure, ignored message, wait condition,
panic/index assumption, and security-relevant zero/canonicality check reached
from the fixed wrapper. The minimum complete matrix is:

| ID | Upstream behavior reached by the fixed path | Production disposition |
| --- | --- | --- |
| `BND-01` | Exact 32-byte digest/scalar/entropy lengths and valid SEC1 points | Preserve with boundary parsers; require compressed 33-byte production points |
| `BND-02` | Canonical scalar parsing; required non-zero private key share | Preserve; zero is allowed only for protocol values whose individual zero value is mathematically valid |
| `BND-03` | Non-empty, duplicate-free participants; `me` present; `2 <= threshold <= N` | Specialize into fixed role types, `N = t = 2`, and compile-fail fixtures |
| `BND-04` | Stage checks for message, start-presign, and take-output | Strengthen into consuming state types with no callable invalid transition |
| `MSG-01` | Header shorter than 40 bytes or unknown header is silently ignored | Strengthen to authenticated malformed-message abort and pair burn |
| `MSG-02` | MessagePack decode/encode and point/scalar decode failures abort | Preserve semantically with strict bounded canonical production decoding |
| `MSG-03` | Unknown/duplicate shared senders and wrong private sender are ignored while waiting | Strengthen to wrong-role/duplicate/reflection abort; external timeout burns state |
| `MSG-04` | Upstream buffering accepts unused waitpoints without a bound | Replace with one expected typed message and hard per-session byte/count ceilings |
| `OT-01` | Base-OT received points reject identity/malformed serialization | Preserve with canonical non-identity point parsing |
| `OT-02` | Base-OT output matrices must have exact 128-by-128 shape | Preserve with fixed arrays and controlled dimension rejection |
| `OT-03` | Correlated-OT `x` and received `u` heights equal the fixed adjusted batch size | Preserve with fixed-size types |
| `OT-04` | Random-OT `small_t` has exactly 128 elements | Preserve before indexing or allocation |
| `OT-05` | For every column, `q_j = t_j + Delta_j * x` | Preserve exactly; failure is a malicious-peer abort |
| `MTA-01` | MTA ciphertext vector length equals the 384-element correlation vector and is non-empty | Preserve with fixed arrays; eliminate upstream `tv[0]` panic |
| `MTA-02` | Multiplication batch count is non-zero and returns exactly one result per peer and triple | Specialize to exactly two triples; missing or excess result aborts |
| `TRI-01` | Degree subtraction, polynomial generation/evaluation, group commitment, hashing, and serialization errors propagate | Preserve as typed terminal errors with secret-free diagnostics |
| `TRI-02` | Each role receives exactly two commitments, confirmations, polynomial/proof vectors, DLogEq vectors, and final-share vectors | Strengthen with length checks before indexing; eliminate upstream malformed-vector panics |
| `TRI-03` | Peer confirmation equals the locally computed ordered-commitment hash | Preserve and bind to pair context plus triple index |
| `TRI-04` | Revealed `E`, `F`, `L` have degrees `1`, `1`, `0` for threshold two | Preserve exactly |
| `TRI-05` | Commitment opening for `(E, F, L)` matches the first-round commitment | Preserve exactly with constant-time commitment comparison |
| `TRI-06` | DLog proofs verify knowledge of peer `e_i(0)` and `f_i(0)` | Preserve with role/triple/context-bound Fiat-Shamir transcripts |
| `TRI-07` | Received private `a_i`, `b_i` evaluations satisfy `a_iG = E(z_i)` and `b_iG = F(z_i)` | Preserve exactly |
| `TRI-08` | DLogEq proof verifies `C_i = e_i(0)F(0)` against `E_i(0)` | Preserve exactly; reject identity alternate generator |
| `TRI-09` | DLog proof verifies knowledge of each multiplication output `ell_i(0)` | Preserve exactly |
| `TRI-10` | Final public sharing polynomial satisfies `L(0) = C` | Preserve exactly |
| `TRI-11` | Received private product share satisfies `c_iG = L(z_i)` | Preserve exactly |
| `PRE-01` | Presign requires two participants, `me` present, threshold within bounds, and both triple thresholds equal the requested threshold | Specialize to fixed roles and threshold two |
| `PRE-02` | Upstream assumes triple participant sets match and performs no explicit check | Strengthen: both triples must carry the exact fixed pair, scope, pair context, generation transcript, and threshold |
| `PRE-03` | Received peer `e'_i` is non-zero | Preserve peer check; reconstructed `e` must also be non-zero before inversion |
| `PRE-04` | Reconstructed `e` satisfies `eG = E` | Preserve exactly |
| `PRE-05` | `alpha G = K + A` and `beta G = X + B` | Preserve exactly |
| `PRE-06` | `e` inversion succeeds | Preserve as controlled abort and burn |
| `RER-01` | Stored `R` equals the rerandomization argument `R` | Specialize into one pair record and retain explicit equality at persistence boundaries |
| `RER-02` | HKDF expansion succeeds and retries until canonical non-zero `delta` | Preserve exact oracle behavior; freeze production KDF vectors |
| `RER-03` | Public entropy is 32 bytes, fresh, and unpredictable | Strengthen with committed two-role contributions and one-use reveal |
| `RER-04` | The upstream one-byte retry counter increments without a checked overflow bound | Strengthen to at most 256 attempts followed by a typed terminal abort; never wrap or panic |
| `RER-05` | Upstream unwraps `delta^-1` after checking `delta != 0` | Specialize with a proved non-zero scalar type; inversion failure remains a controlled terminal abort |
| `SIG-01` | Actual message digest is exactly 32 bytes and authorized before scalar reduction | Preserve at the Router/SigningWorker boundary |
| `SIG-02` | Signature share uses exact Lagrange, rerandomized `k`, `sigma`, digest, and `R` | Preserve and prove algebraically |
| `SIG-03` | Low-`s` normalization occurs before final verification | Preserve with constant-time conditional selection |
| `SIG-04` | Final verification rejects zero `r`, zero `s`, high `s`, or a failed ECDSA equation | Preserve exactly |
| `SIG-05` | Recovery ID must recover the registered key for the exact digest | Preserve; normalization and recovery-ID derivation form one operation |
| `USE-01` | Upstream documentation requires triple and presign outputs to be destroyed after use | Enforce atomic `available -> reserved -> committed_use -> destroyed` transitions on both roles |
| `ABT-01` | Any propagated cryptographic, encoding, channel, proof, equality, or index error terminates the upstream future | Preserve as one typed terminal abort; peer reconciliation burns matching state |
| `ABT-02` | Upstream can wait indefinitely for absent messages | Add authenticated deadlines; timeout is terminal and burns the pair |
| `ABT-03` | Upstream batched paths can panic on malformed vector lengths | Eliminate every panic/index path; malformed peer input produces a controlled abort |

The inventory links each row to exact pinned source lines and splits combined
rows when multiple source expressions have different target owners. A source
scanner and reviewed call graph fail the inventory gate when a reachable
`return Err`, `?`, `unwrap`, `expect`, `assert`, unchecked index, ignored
message, or wait path lacks a disposition.

### Oracle corpus contract

`router-ab-ecdsa-near-oracle-tests` is a dev/test-only crate. Its manifest and
fixtures are immutable inputs to Phase 5 and include:

1. A named deterministic randomness stream for every role, triple, OT/MTA
   subprotocol, proof nonce, commitment randomizer, and entropy contribution.
2. Layer vectors for base OT, correlated OT, random OT, MTA, multiplication,
   each triple, presigning, rerandomization, Client share computation,
   SigningWorker combination, low-`s`, recovery ID, and final verification.
3. Full party-view snapshots after every logical round. Secret fixtures are
   marked test-only and excluded from packages, examples, logs, and release
   artifacts.
4. Exact `near-oracle-v1` messages, transcript digests, commitments, proof
   challenges, outputs, errors, and abort point for valid and invalid cases.
5. Normalized semantic events for the final production transcript/codec:
   role, phase, round, equation inputs/outputs, check ID, state transition, and
   abort class.
6. A four-case matrix: NEAR/NEAR source execution, new Client against a
   captured NEAR SigningWorker semantic trace, a captured NEAR Client semantic
   trace against the new SigningWorker, and new/new. The source execution has
   exact NEAR byte/transcript vectors. Role replay compares normalized values,
   proof inputs, checks, outputs, aborts, and state; it does not claim wire
   interoperability between transcript profiles.
7. At least one one-field mutation for every critical-check/abort ID, including
   malformed and identity points, noncanonical scalars, shortened and extended
   vectors, invalid commitments/proofs, failed OT consistency, wrong context,
   wrong role, replay, reflection, reorder, duplicate, stale epoch, entropy
   equivocation, timeout, crash, rollback, duplicate consume, invalid low-`s`,
   invalid recovery ID, and failed final verification.
8. Positive vectors covering both low-`s` branches, ordinary recovery IDs,
   both OT directions, both roles, two distinct scope/key epochs, and multiple
   deterministic seeds. Synthetic online vectors exercise all recovery-ID
   parser branches even when a branch is negligibly reachable from honest key
   generation.
9. A machine-readable coverage index mapping every fixture to construction
   step, check ID, assumption ID, proof target, expected party views, expected
   terminal state, and expected result.

Exact-count commands fail when a fixture, role, phase, check ID, proof target,
or four-case matrix entry is absent. The deterministic RNG, oracle codec, and
NEAR dependency are unreachable from production features and rejected by
release graph/symbol scans.

### Formal assumption ledger

The ledger is normative and versioned. Every entry records its statement,
scope, consumers, cited construction, enforcement/evidence, failure impact,
owner, reviewer, and disposition.

| ID | Frozen assumption or explicit claim boundary |
| --- | --- |
| `A-ROLE` | Exactly two signing roles exist; one role may be statically corrupted for the full lifetime of an activated wallet key; the roles do not collude |
| `A-GROUP` | secp256k1 group operations and canonical encodings are correct; discrete logarithm is hard in the selected group |
| `A-HASH` | SHA-256, SHA3-256, HKDF, commitment hashes, and Fiat-Shamir transcript hashes provide the properties required by their cited uses and domain separation is collision-free at the protocol level |
| `A-OT` | The exact Chou-Orlandi base OT and repaired KOS/SoftSpoken-style extension instantiated by the fixed code provide the required malicious OT security; independent review must close the implementation-to-paper mapping |
| `A-MTA` | The exact HMRT21-style multiplication provides private additive product shares, and the committed-triple checks detect incorrect products except with negligible probability |
| `A-PROOF` | DLog and DLogEq Fiat-Shamir proofs are sound and zero-knowledge for fresh nonces and the frozen transcripts |
| `A-RNG` | Each honest role has a cryptographic RNG; named production random values are independent, fresh, secret where required, and never reused |
| `A-ENTROPY` | Commitment-bound role contributions make rerandomization entropy unpredictable before committed use when either role is honest |
| `A-CHANNEL` | Private messages have end-to-end confidentiality, integrity, sender authentication, and session binding; public messages have integrity, sender authentication, and consistent context |
| `A-REGISTRY` | The authenticated registry uniquely binds scope, role, public-share commitment, combined public key, protocol version, and epochs before protocol work |
| `A-STATE` | Atomic persistence and tombstones enforce one-use transitions; rollback protection and epoch invalidation prevent revival |
| `A-DIGEST` | The 32-byte signing input is the exact authorized EVM digest; arbitrary unhashed scalar signing is unreachable |
| `A-CT` | Secret-bearing production kernels satisfy the separate source and compiled native/Wasm constant-time gate |
| `A-ERASURE` | Recoverable exits zeroize owned buffers; platform copies and unrecoverable termination follow the documented memory-destruction boundary |
| `A-AVAIL` | A malicious role or network can always cause abort; availability, fairness, robustness, and blame remain explicit non-claims |
| `A-ADAPTIVE` | Adaptive or mobile compromise that reaches both roles, both-role compromise, traffic-analysis privacy, and post-compromise recovery remain explicit non-claims |

An assumption may move into a proved/enforced claim only through a reviewed
ledger update. Missing owners, evidence, citations, or failure impacts block
approval.

### Phase 4 formal proof requirements

The approved Verus-first proof inventory is:

1. Fixed role identifiers imply interpolation coordinates `2` and `3`, with
   `lambda_C = 3` and `lambda_S = -2`.
2. Mapping additive shares through inverse Lagrange coefficients preserves
   `x = d_C + d_S` and `X = xG`.
3. Accepted triple postconditions imply reconstructed
   `A = aG`, `B = bG`, `C = cG`, and `c = ab`, assuming the OT/MTA and proof
   ledger entries.
4. Accepted presign checks and valid triples imply
   `R = k^-1 G` and reconstructed `sigma = kx`.
5. Non-zero rerandomization preserves
   `R' = (k/delta)^-1 G` and `sigma' = kx/delta` for `tweak = 0`.
6. The two online shares combine to
   `s = (k/delta)(h + rx)`, and the resulting `(r, s)` satisfies the ECDSA
   verification relation when inputs meet the model preconditions.
7. Low-`s` normalization preserves validity and its recovery-ID adjustment
   recovers the same registered key.
8. The typed state machine permits only
   `available -> reserved -> committed_use -> destroyed`; every success,
   rejection, abort, timeout, crash-recovery, and ambiguous-delivery path ends
   with no reusable secret material.
9. Context, role, round, triple index, proof kind, and sequence fields make
   replay, reflection, reorder, cross-key, cross-epoch, and cross-pair messages
   inadmissible in the model.

OT privacy/soundness, DLog/DLogEq cryptographic soundness, hash assumptions,
CSPRNG quality, erasure, and compiled constant-time execution remain ledger
assumptions with separate evidence. Aeneas/Lean and a fresh end-to-end UC proof
remain deferred non-claims.

### Required Phase 4 artifacts

- `crates/router-ab-ecdsa-presign/specs/fixed-2p-v1.md`: normative
  construction, messages, equations, party views, state machine, and aborts.
- `crates/router-ab-ecdsa-presign/specs/transcript-v1.md`: both transcript
  profiles, numeric tag/message registry, exact encodings and bounds, domain
  strings, challenge inputs, complete byte vectors, and KDF vectors.
- `crates/router-ab-ecdsa-presign/specs/upstream-check-inventory.md`: exhaustive
  source-to-target check and abort mapping.
- `crates/router-ab-ecdsa-presign/specs/adversary-model-v1.md`: claims,
  corruption model, transport model, exclusions, and composition boundary.
- `crates/router-ab-ecdsa-presign/formal-verification/docs/assumptions.md`:
  normative assumption ledger.
- `crates/router-ab-ecdsa-presign/formal-verification/docs/proof-inventory.md`:
  the nine approved Verus targets and anti-drift links.
- `crates/router-ab-ecdsa-near-oracle-tests/fixtures/v1/manifest.json`: source,
  toolchain, harness, exact counts, coverage index, and fixture digests.
- `docs/security/router-ab-ecdsa-phase4-review.md`: immutable design-review
  record and artifact digests.

### Independent design-review approval

At least one cryptography reviewer who authored none of the normative Phase 4
artifacts and is not assigned as a Phase 5 implementation author reviews the
design before Phase 5 begins. The reviewer receives the clean pinned source,
fixed-path call graph, normative specs, every check/abort mapping, oracle corpus
and coverage report, proof inventory, assumption ledger, API manifests, and all
deliberate divergences.

Approval explicitly confirms:

1. The construction stack and fixed parameters match the pinned code and cited
   protocol variants.
2. The repaired KOS/SoftSpoken consistency check used by the code supports the
   `A-OT` claim, or the claim/construction is revised before approval.
3. Every reachable upstream security check, abort, ignored-message path,
   indefinite wait, panic, and unchecked index has one reviewed disposition.
4. Party views expose no additional secret relative to the accepted fixed
   construction.
5. Equations, transcripts, domain separation, unique session identifiers,
   joint entropy, and proof statements are complete and unambiguous.
6. The oracle corpus covers every matrix row and distinguishes exact upstream
   bytes, semantic role-replay parity, production transcript vectors, and
   deliberate hardening differences.
7. The formal proof boundary and assumption ledger support the exact limited
   release claim.
8. The fixed public API contains only Client and SigningWorker operations and
   preserves the approved SDK behavior.

The review result is `approved` or `rejected`. Security-relevant conditions and
follow-ups produce `rejected` until closed. The signed record includes reviewer
identity, date, reviewed commit, source tree, every artifact digest, findings,
resolutions, accepted non-claims, and final decision. Any later change to a
reviewed construction, equation, transcript field, proof relation, critical
check, randomness source, state transition, or codec invalidates approval and
requires a scoped re-review.

Approval evidence follows the existing Ed25519 Yao Phase 2B governance shape:
an `independent_reproducer` and a `cryptographic_reviewer` have distinct,
externally pinned Ed25519 verification keys, authority IDs, and non-zero key
epochs. The reproducer signs the canonical reproduction record first. The
reviewer signs a domain-separated canonical approval payload that commits the
reviewed source commit/tree, clean-source digest, complete artifact-set digest,
reproduction-record digest, review-report digest, accepted non-claims,
decision, policy version, reviewer key epoch, and monotonic approval sequence.
The verification task rejects unknown fields, duplicate fields, noncanonical
encodings, weak or reused authorities, stale sequences, digest drift, and a
reviewer who also authored the implementation or reproduction record. The
repository stores evidence; the trusted policy digest and reviewer key remain
published through an independently authenticated channel.

### Historical implementation ledger

#### Phase 4A: time-boxed provenance scaffold

Target: half a working day. Stop expanding scaffolding when the source is
reproducible and the implementation team can inspect the fixed path.
Phases 4A and 4B share a one-working-day bootstrap budget.

- Create the smallest dev/test-only oracle crate that pins the NEAR commit,
      Git tree, clean source/archive digest, lockfile, and isolated
      `CARGO_HOME` recipe.
- Record the local wrapper entry point and a reviewed function/module path
      through OT/MTA, triples, proofs, presign, rerandomization, and online
      combine. Defer exhaustive edge and error enumeration to Phase 4C.
- Add one dependency check proving the new purpose-built crates' normal and
      build features do not select the oracle crate or `threshold-signatures`.
- Provide one command that builds or runs the oracle harness from a clean
      checkout. Defer elaborate task runners, symbol scans, and exact-count
      infrastructure.

#### Phase 4B: critical-path draft and oracle seed

- Write an implementation draft containing the fixed roles, participant
      coordinates, Lagrange mapping, triple/presign/rerandomization/signing
      equations, malicious-with-abort boundary, party views, randomness, and
      joint-entropy flow.
- Map the critical security subset first: canonical scalar/point parsing,
      fixed-role binding, OT dimensions and consistency, triple
      commitment/proof checks, presign consistency equations, transcript and
      session uniqueness, non-zero rerandomization, one-use destruction,
      low-`s`/recovery coupling, and final signature verification.
- Capture one deterministic valid NEAR execution through triples, presign,
      rerandomization, share combination, and final verification. Freeze its
      inputs and final outputs immediately; add intermediate values as the
      prototype reaches each layer.
- Add a small smoke set covering malformed canonical input, one failed
      proof or commitment, one failed presign equation, and duplicate use.
      Complete mutation coverage remains in Phase 4D.
- Write the narrow Client and SigningWorker Rust API sketch. Defer generated
      Wasm/TypeScript manifests and negative compile fixtures until the API has
      survived the first vertical slice.

#### Phase 4 bootstrap gate

Passing this gate unlocks the isolated Phase 5 prototype:

- Pinned oracle provenance reproduces with one command.
- One deterministic end-to-end valid vector is available.
- The implementation draft fixes the roles, equations, adversary boundary,
      critical transcript bindings, randomness, and deliberate divergences.
- Every critical bootstrap check has an upstream location and intended
      production disposition; lower-risk omissions are recorded for Phase 4C.
- Production dependency selection excludes the NEAR oracle.

No source scanner, full invalid corpus, exact-count guard suite, completed
formal proof, or signed approval is required to begin the isolated prototype.

#### Phase 4C: progressive exhaustive mapping and specification closure

Phase 4C runs alongside the Phase 5 prototype. Assurance follows the code
vertically: OT/MTA, triples, presign, and online signing each close their own
mapping before that subsystem is considered complete.

- Inventory every reachable upstream error, proof/equality check,
      canonicality/zero check, ignored message, wait path, panic, assertion,
      unchecked index, and randomness/session requirement.
- Assign every item one disposition, target owner, corpus case, proof or
      assumption ID, confidence, and reviewer status.
- Reconcile each implemented subsystem with its completed inventory before
      beginning optimization or claiming parity for that subsystem.
- Use a source scanner or exact-count automation where it cheaply prevents
      omissions. A reviewed manual ledger is sufficient where automation would
      delay implementation without adding meaningful coverage.
- Close the complete inventory before the normative specification freeze.
      Every frozen requirement must trace to an inventory row, deliberate
      strengthening, or reviewed fixed-setting exclusion.

#### Phase 4D: normative freeze, oracle corpus, and formal closure

Phase 4D begins once the progressive inventory and first vertical prototype
provide a stable review subject. It has no Phase 3 execution dependency.

- Reconcile and freeze the construction, adversary model, party views,
      equations, state machine, randomness inventory, transcript profiles, and
      exact abort semantics.
- Assign and freeze every numeric transcript tag, transport message code,
      field order, role/proof/subprotocol value, abort code, and message bound;
      generate the complete canonical byte-vector registry.
- Generate deterministic layer/full-session vectors, full party views, one
      invalid mutation for every check/abort ID, and the complete four-case
      source/role-replay/new-new matrix.
- Scaffold the Verus models, nine-proof inventory, assumption ledger, and
      production-to-model anti-drift tests under the new owners.
- Freeze positive Rust/Wasm/TypeScript API manifests and negative compile
      fixtures after the role API stabilizes.
- Add the smallest useful exact-count and release guards for oracle
      provenance, critical coverage, proof targets, API surface, and production
      exclusion.
- Prove every normative check, abort, proof, random value, message field,
      and exclusion has a Phase 4C inventory owner.

#### Phase 4E: independent approval

Phase 4E starts after Phase 4D, the Phase 3 exit, and a reviewable Phase 5
prototype. The reviewer evaluates the frozen online seam and implementation
slice together with the complete Phase 4 artifact set.

- Reproduce the oracle corpus in a clean environment and verify every
      recorded digest.
- Complete independent cryptographic design review, close every
      security-relevant finding, and commit the signed immutable review record.
- Freeze the reviewed artifact set. Subsequent changes use scoped review
      invalidation rather than modifying the approved record.

### Exit Gate

- The clean pinned oracle is reproducible and has zero production
      dependency edges, symbols, features, packages, or release artifacts.
- The fixed protocol specification covers every production transition,
      message, equation, party view, random value, proof statement, challenge,
      abort, and output.
- Every reachable upstream check and abort source has a reviewed mapping
      with confidence at least `0.80`; every security-critical mapping is
      `1.00` or explicitly accepted by the independent reviewer.
- The adversary model, claim boundary, transport/storage assumptions,
      exclusions, and joint-entropy construction are frozen without ambiguity.
- The oracle manifest covers every role, layer, phase, four-case oracle
      matrix entry, check ID, abort ID, state transition, and API fixture with
      exact counts.
- The nine Verus targets, anti-drift suite, and assumption ledger run
      through pinned exact-count commands and fail when any target is omitted.
- Independent reproduction matches the frozen oracle corpus and API
      manifests.
- The independent review record is `approved`, contains every reviewed
      artifact digest, and has no open security-relevant condition.

## Phase 5: Build the Purpose-Built Fixed 2-of-2 Presign Core

Status: **isolated cryptographic prototype complete through the
storage-independent persistent-pool domain model; production promotion and
concrete adapters remain in Local Phases A and B**

Goal: implement the fixed Client plus SigningWorker protocol directly from the
implementation draft, then converge on the frozen specification and reviewed
protocol references. NEAR code remains only inside the oracle harness.

### Phase 5A: isolated vertical prototype

- [x] Create `router-ab-ecdsa-presign` with no normal or build dependency on
      `threshold-signatures`.
- [x] Implement only the required secp256k1 OT, multiplication,
      triple-generation, commitment, DLog/DLogEq proof, and presign primitives.
- [x] Drive one fixed new Client/new SigningWorker session end to end with
      deterministic test randomness and typed in-process messages. Skip Wasm,
      SDK, Worker, persistence, compact codec, broad fuzzing, and size
      optimization in this lane.
- [x] Compare the successful session's intermediate equations, role-visible
      values, and final presign outputs with the Phase 4 oracle seed.
- [x] Implement the critical bootstrap checks on the paths exercised by the
      vertical slice and return typed terminal aborts for failures.
- [x] Record gaps and continue into Phase 5B once one new/new happy path and the
      small Phase 4B negative smoke set pass.

#### Implementation checkpoint 1: presign equations from validated triples

Completed in the isolated crate graph:

- fixed Client and SigningWorker wire messages with implicit role identity and
  fixed scalar/point widths;
- consuming role-specific states for the two NEAR-compatible presign rounds;
- additive-share conversion using fixed coordinates `2` and `3` and fixed
  Lagrange coefficients `3` and `-2`;
- strict compressed-point parsing, canonical-scalar parsing, pair-context
  binding, non-zero `e` checks, and the `E`, `alpha`, and `beta` commitment
  equations;
- zeroization for secret inputs, in-flight states, messages, and outputs;
- one deterministic new/new vector plus exact `R`, `k`, and `sigma` parity with
  the pinned NEAR oracle for both roles;
- smoke tests for noncanonical scalar input, zero `e`, cross-context input, and
  a tampered additive-round share; and
- a production dependency check that rejects either the oracle crate or
  `threshold-signatures` from the normal/build graph.

This checkpoint begins with already validated committed triple shares. The
next vertical slice adds proof-checked triple generation through OT, MTA,
commitments, and DLog/DLogEq before the broader negative corpus, codec, Wasm,
SDK, Worker, and persistence work.

#### Implementation checkpoint 2: proof kernels and triple boundary

Completed in the isolated crate graph:

- every presign message and triple record is bound to both the signing-scope
  digest and presign-pair context digest;
- fixed-role Schnorr DLog and Chaum-Pedersen DLogEq kernels implement the
  equations used by the pinned NEAR triple generator;
- Fiat-Shamir challenges bind scope, pair, triple index, prover role, proof
  type, proof kind, statements, and commitments through a fixed tagged
  SHA-256 transcript;
- production proof APIs generate fresh non-zero nonces from `CryptoRngCore`;
  deterministic nonce injection exists only in unit-test and oracle builds;
- proof witnesses and test nonces are non-cloneable, non-debuggable, and
  zeroized on drop;
- context substitution, role reflection, response tampering, zero nonce, and
  statement/witness mismatch tests return typed terminal errors;
- deterministic production proof vectors are frozen, while pinned NEAR proof
  vectors confirm the same Schnorr and Chaum-Pedersen equations across the two
  transcript profiles; and
- raw triple scalars can no longer enter the production presign API. The API
  accepts an opaque `ValidatedTriple` that the checked triple generator will
  own; raw construction is confined to test/oracle compilation.

#### Implementation checkpoint 3: fixed polynomial commitments

Completed in the isolated crate graph:

- fixed degree-one `E` and `F` polynomials and a fixed degree-zero `L`
  polynomial replace generic vectors and runtime degree parameters;
- each coefficient is generated from `CryptoRngCore`, exact degree is enforced
  by bounded non-zero sampling, and secret coefficients zeroize on drop;
- coefficient commitments use the NEAR-compatible `coefficient * G`
  equations;
- a canonical SHA-256 commit/open transcript binds the signing scope, pair,
  triple index, prover role, five compressed coefficient commitments, and a
  32-byte opening randomizer;
- commitment-digest verification and private-share point equations use
  constant-time comparisons;
- opening verification emits an opaque value that retains the context and
  triple-index binding required by the later private-share check;
- fixed Client-to-SigningWorker and SigningWorker-to-Client share APIs evaluate
  only at coordinates `3` and `2`, respectively;
- context substitution, triple-index substitution, role reflection, altered
  opening, and altered private-share tests return typed terminal errors; and
- the oracle corpus freezes one deterministic opening and checks the pinned
  NEAR equations `E(z) = eG` and `F(z) = fG`.

#### Limited-resource critical path

The active implementation lane prioritizes only work required to establish a
secure, end-to-end fixed two-party ECDSA session:

1. base random OT and malicious OT extension;
2. fixed-size MTA for exactly two triples;
3. proof integration and terminal triple validation; and
4. one complete generated-triple presign and signing oracle session.

Compact codecs, Wasm packaging, SDK/Worker integration, broad formal coverage,
large fuzz corpora, size polishing, deployment, and deletion remain deferred
until this lane succeeds. The lane still preserves critical boundary parsing,
session/role binding, abort checks, zeroization, deterministic oracle evidence,
and production dependency isolation.

#### Implementation checkpoint 4: fixed base random OT

Completed in the isolated crate graph:

- exactly 128 Diffie-Hellman base random OTs produce fixed 16-byte keys;
- fixed Client-sender/SigningWorker-receiver and reverse role APIs replace
  runtime role selection;
- consuming sender states and sealed outputs prevent key reuse or extraction by
  production callers;
- the KDF binds scope, pair, triple index, base-ROT sender role, OT index,
  branch, `Y`, `X`, and the Diffie-Hellman point;
- receiver choice application uses constant-time point selection;
- all received points reject invalid or identity encodings, while `X - Y`
  identity and receiver-generated degenerate points abort;
- sender scalars, receiver choices, and derived keys zeroize on drop;
- context substitution, degenerate points, and role reflection have targeted
  negative tests; and
- the oracle corpus freezes the receiver choices and boundary sender/receiver
  keys while checking all 128 correlation equations.

The remaining critical implementation step is one complete new/new
generated-triple presign and online-signing session.

##### Critical pinned-oracle divergence: OT row expansion

The pinned NEAR implementation cannot serve as an exact-output oracle for OT
extension. In `triples/bits.rs:320-327`, `expand_transpose` updates
`hasher_row` with the base-OT row key and then finalizes a new clone of the
unkeyed prefix. The expanded rows therefore omit every base-OT key. For the two
receiver branches this yields identical `t0` and `t1`; the transmitted
`u = t0 xor t1 xor x` collapses to `x` and exposes the receiver's extension
choice bits.

Disposition: critical upstream mismatch. Finding confidence: `1.00`. The
purpose-built extension uses the intended keyed expansion, retains NEAR's
correlation equations and malicious consistency abort, and includes a
regression proving that changing any base-OT key changes the expanded row.
Oracle parity for this function is explicitly forbidden. Independent review
must approve the corrected extension before MTA output can enter triple
generation.

#### Implementation checkpoint 5: corrected malicious random-OT extension

Completed in the isolated crate graph:

- fixed 128-base-OT, 768-output, 1024-padded-row protocol shapes replace
  variable batch sizes;
- role-specific consuming states implement correlation, post-correlation
  challenge, consistency proof, verified acceptance, and sealed output;
- every expansion binds the base key, scope, pair, triple index, sender role,
  base index, branch, and block;
- the sender checks all 128 KOS-style correlation equations through one
  constant-time aggregate result before output;
- the receiver releases output only after the sender's authenticated acceptance
  transition;
- base-ROT session and role bindings survive into the extension and reject
  cross-session or reflected use;
- secret matrices, choices, base material, and scalar outputs zeroize on drop;
- tests cover all 768 correlations in both role directions, altered-proof
  abort, context substitution, and sensitivity to every base-key branch; and
- the deterministic corpus freezes the corrected challenge, acceptance,
  choices, and boundary outputs while explicitly excluding faulty NEAR bytes.

The exact construction and pinned-source mapping are in
`crates/router-ab-ecdsa-presign/specs/random-ot-extension-v1.md`. Mapping
confidence is `1.00` for the fixed shape, correlation equations, consistency
check, carry-less multiplication, and upstream expansion defect; the
domain-separated scalar-output adaptation is `0.98`.

The remaining critical implementation step is one complete new/new
generated-triple presign and online-signing session.

#### Implementation checkpoint 6: fixed MTA and two-party multiplication

Completed in the isolated crate graph:

- every corrected 768-output random-OT result is split into exactly two fixed
  384-OT MTA instances;
- instance 0 computes the `a_sender * b_receiver` cross term and instance 1
  computes `b_sender * a_receiver`;
- Client is the fixed sender for Triple 0 and SigningWorker is the fixed sender
  for Triple 1, eliminating runtime role ordering;
- consuming sender states retain fresh masks until a context-bound response
  supplies the receiver's first coefficients and seeds;
- receiver seeds are sampled only after ciphertext and binding validation;
- fixed arrays and canonical scalar parsing replace generic vectors and length
  checks;
- operands, messages, state, masks, derived coefficients, and sealed additive
  multiplication shares zeroize on drop;
- both role directions reconstruct
  `(a_client + a_worker) * (b_client + b_worker)` in targeted tests;
- role-specific bundle types require exactly an ordered Triple 0 and Triple 1
  share under one context before the next layer can consume multiplication;
- context substitution, wrong triple assignment, and noncanonical ciphertexts
  abort at their boundaries; and
- an altered-ciphertext test confirms that corruption breaks the terminal
  product equation which the next checkpoint must reject.

The exact equations and pinned-source mapping are in
`crates/router-ab-ecdsa-presign/specs/fixed-mta-v1.md`. Mapping confidence is
`1.00` for the MTA equations, the two cross-term composition, and local-product
aggregation; fixed role scheduling is `0.99`, and the domain-separated
coefficient derivation is `0.98`.

The remaining critical implementation step is one complete generated-triple
presign and online-signing oracle session.

#### Implementation checkpoint 7: committed-triple finalization

Completed in the isolated crate graph:

- polynomial openings, verified peer evaluations, fixed MTA outputs, and all
  DLog/DLogEq proofs are joined under one pair context and fixed triple index;
- each role proves knowledge of its `E(0)`, `F(0)`, and sealed MTA-output
  scalar, plus the DLogEq relation `C_i = e_i(0)F(0)`;
- the initial degree-zero `L` randomness is used as the slope of the final
  product-sharing polynomial, matching the pinned NEAR construction;
- raw MTA shares stay local and finalization messages carry only
  recipient-scoped masked evaluations `l0_i + r_i z_peer`;
- each role verifies its reconstructed `a`, `b`, and `c` shares against the
  aggregate public polynomials at its fixed coordinate;
- both roles enforce `sum C_i = sum l0_i G` before the checked state machine
  constructs an opaque `ValidatedTriple`;
- a deterministic two-triple session reconstructs and verifies `A`, `B`,
  `C`, and `c = ab`, and freezes one semantic output digest;
- a ciphertext-level MTA corruption reaches finalization with locally valid
  share proofs and is rejected by both roles at the terminal product equation;
  and
- the exact equations, pinned source ranges, and mapping confidence are in
  `crates/router-ab-ecdsa-presign/specs/committed-triple-finalization-v1.md`.

#### Implementation checkpoint 8: complete generated-triple signing slice

Completed in the isolated crate graph:

- both generated `ValidatedTriple` pairs feed directly into the fixed Client
  and SigningWorker presign states;
- additive key shares reconstruct the exact wallet public key and the presign
  checks enforce `eG = E`, `alpha G = K + A`, and `beta G = X + B`;
- the two roles produce one common `R` and role-local `k` and `sigma` shares;
- `router-ab-ecdsa-online` now implements the SigningWorker half alongside the
  Client kernel: identical public rerandomization, fixed `-2` Lagrange
  weighting, signature-share combination, low-`s`, final prehash verification,
  and recovery-ID selection;
- the deterministic new/new session runs base OT, corrected malicious OT
  extension, MTA, committed triples, presign, Client online share, and
  SigningWorker finalization;
- the online fixture's Client share and 65-byte final signature match the
  pinned NEAR oracle exactly; and
- the final signature semantic digest is frozen as
  `60add26fae8c128e2004500ab22d87ee1f363a71b7aa0176f3ae445b16276f1d`.

The limited-resource cryptographic prototype has reached its intended vertical
milestone. The next work belongs to Phase 5B: tighten role-state/API coverage,
add one-use lifecycle semantics, close the remaining negative smoke cases, and
measure the purpose-built native/Wasm artifacts before codec or SDK work.

### Phase 5B: parity, hardening, and promotion

- [x] Define fixed role-specific Client and SigningWorker presign and online
      typestate sequences. The public API accepts no participant vector,
      runtime participant ID, runtime threshold, or role selector.
- [x] Represent reachable cryptographic role states with dedicated typestate
      structs and exact transition inputs.
- [x] Make transitions consume the prior state by value. Secret-bearing states
      expose no `Clone`, `Copy`, `Debug`, broad serialization, or reusable
      completed-session API.
- [x] Use compile-time participant identities, role ordering, threshold, round
      counts, and bounded message sizes.
- [x] Use explicit synchronous transitions without boxed generic protocol
      traits, futures tasks, dynamic maps, or general threshold machinery.
- [x] Keep in-kernel secret inputs and intermediate values in fixed-size types
      with zeroization on completion, abort, drop, and failed transition.
- [x] Enforce consuming in-kernel
      `available -> reserved -> committed-use -> consumed/drop` transitions
      before any online share or final signature is emitted.
- [x] Define a storage-independent record schema, exact identity bindings,
      monotonic compare-and-swap mutations, forward-only lifecycle, and
      terminal tombstones for timeout, ambiguous delivery, crash, peer abort,
      success, and rejection.
- Implement Client and SigningWorker persistence adapters that atomically
      apply reserve/commit/destroy transitions and delete sealed material.
      Never return either pair half to the available pool.
- Bind key-share inputs to the authenticated public-share commitment
      registry and prove the two commitments add to the exact wallet public
      key before creating pool material.
- [x] Keep all NEAR MessagePack decoding, transcript capture, and cross-party
      adaptation in `router-ab-ecdsa-near-oracle-tests`. The purpose-built
      crates expose one production protocol profile and contain no oracle-wire
      branch, legacy flag, or alternate decoder.
- Replay captured NEAR SigningWorker semantic traces into the purpose-built
      Client, replay captured NEAR Client semantic traces into the
      purpose-built SigningWorker, and execute purpose-built against
      purpose-built across the complete valid and invalid corpus. The dev/test
      harness compares canonical semantic events, proof inputs, equations,
      party views, outputs, and abort classes.
- [x] Add compile-fail/API tests proving an available presignature cannot emit
      an online share and a reserved value cannot be committed twice.
- Extend compile-fail/API coverage across every role, threshold,
      participant-set, and transition-input escape hatch.
- [x] Add automated dependency, source, and Wasm resolved-graph guards
      rejecting the NEAR crate, futures, unrelated curves/protocols, and
      generic threshold surfaces from the isolated purpose-built crates and
      online Client wrapper.
- Add compiled native/Wasm symbol and section guards, then extend every
      guard to the replacement presign Client and SigningWorker wrappers before
      deleting their current NEAR-backed implementations.
- Record code size, allocations, copies, indirect calls, peak memory,
      rounds, payload, and presign throughput.

#### Implementation checkpoint 9: one-use online kernel and oracle isolation

Completed in the isolated crate graph:

- `router-ab-ecdsa-online` exposes separate Client and SigningWorker
  `available`, `reserved`, and `committed-use` types;
- every lifecycle transition consumes its input, and share/final-signature
  functions accept only the committed role state;
- committing binds the one-use material to the expected presignature point;
- errors and successful completion drop zeroizing material, while Rust's type
  system prevents an in-process retry with the consumed value;
- compile-fail checks cover reuse after reservation and direct signing from
  available material;
- negative tests reject an altered Client share, a cross-presignature
  commitment, and an unrelated group public key;
- exact Client-share and final-signature comparison with the pinned NEAR
  implementation now lives only in `router-ab-ecdsa-near-oracle-tests`;
- oracle-owned source and resolved dependency-graph tests prevent generic
  threshold machinery, futures, and unrelated curve libraries from entering
  the isolated production crates or online Client Wasm graph;
- the release browser artifact measures 68,477 bytes raw, 31,430 bytes with
  gzip level 9, and 26,282 bytes with Brotli level 11; and
- the ARM64 release constant-time scan reports no findings in the secret
  signature-share arithmetic or low-`s` selection. Its remaining warnings are
  public boundary parsing and the public expected-point mismatch branch.

The lifecycle and requirement map is frozen in
`crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md`. Concrete atomic
persistence adapters, authenticated commitment-registry binding, complete
invalid-corpus replay, compiled native/Wasm guards, and compiled-Wasm
constant-time evidence remain open production-promotion work.

#### Implementation checkpoint 10: persistent pool contract

Completed in the isolated crate graph:

- `router-ab-ecdsa-pool` defines the exact wallet, account, scope, pair, role,
  key epoch, activation epoch, protocol, request, and reservation bindings;
- the persisted domain has only available, reserved, committed-use, and
  absorbing tombstone states with monotonic revisions;
- every valid transition emits one exact compare-and-swap mutation, and every
  terminal mutation identifies the sealed material that the adapter must
  delete in the same transaction;
- success, rejection, binding substitution, timeout, cancellation, crash,
  peer abort, ambiguous delivery, persistence failure, expiry, and epoch
  retirement permanently burn the pair half;
- unit tests cover stale reservation races, late or substituted commits,
  destructive recovery, expiry, retirement, and post-commit material expiry;
- a compile-fail test proves a tombstone cannot be reserved or revived; and
- the production dependency and source guards now include the pool crate.

The contract and requirement map are frozen in
`crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md`. Concrete
IndexedDB and SigningWorker adapters remain Phase 7 integration work because
only those storage owners can prove transactional replacement, material
deletion, crash recovery, and output release ordering.

### Exit Gate

- Phase 4E independently approves the final construction, complete check
      mapping, oracle evidence, formal boundary, and reviewable implementation
      subject.
- Purpose-built Client and SigningWorker sessions match the oracle's
      equations, role-visible values, outputs, and abort behavior; production
      transcript bytes match the separately frozen `transcript-v1` vectors.
- The implementation exposes only fixed two-party role APIs and contains no
      production NEAR dependency or generic protocol runtime.
- The bounded design review approves the fixed-path state machine,
      critical-check mapping, and differential parity before the wire codec
      changes.

## Phase 6: Add the Compact Canonical Codec and Final Slimming

Status: **open; fixed in-memory wire values exist, while the compact canonical
presign transport codec remains Local Phase C**

Goal: implement the exact production wire frozen in Phase 4 and remove generic
serialization from the purpose-built protocol.

### Historical implementation ledger

- Implement the Phase 4 numeric registry and bounded canonical encoding
      with its fixed tags, lengths, endianness, role ordering, domain
      separation, message ceilings, and rejection rules.
- Keep transport and transcript encodings distinct where their security
      purposes differ.
- Implement strict one-pass decoders that reject unknown tags, trailing
      bytes, noncanonical integers/scalars/points, oversize lengths, duplicate
      fields, and wrong-role messages.
- Freeze independent codec vectors plus commitment, proof-challenge, and
      complete-transcript vectors before promotion.
- Assign one new purpose-built presign protocol/wire identifier. Preserve
      the ECDSA key and additive shares; destroy old development presignature
      pools at cutover.
- Prove the final release graph contains no `rmp-serde`, generic serde
      decoder, futures, NEAR threshold dependency, oracle transcript profile,
      or alternate wire decoder. The pinned semantic oracle remains available
      only to dev/test anti-drift tooling.
- Run the full valid, invalid, inter-process, parser-fuzz, and
      independently reproduced transcript corpus against the final codec.
- Measure raw/gzip/Brotli, parse, compile, instantiate, peak memory,
      payload, rounds, and presign throughput against the Phase 0 baseline.
- Require the purpose-built presign artifact to meet the frozen hard budget
      and target 400 KiB gzip or less.
- Extend the bounded independent review to the final state-machine,
      transcript, challenge, and codec composition, focusing on any semantic
      divergence from the frozen oracle.

### Exit Gate

- Fixed Client and SigningWorker sessions pass the complete fixed-path
      oracle,
      differential, adversarial, fuzz, and inter-process corpus.
- The canonical corpus is independently reproduced byte for byte.
- The purpose-built presign artifact meets the approved size, latency,
      memory, payload, and pool-throughput budgets.
- Generic codecs, generic state machinery, alternate wire paths, and
      forbidden dependencies are absent.

## Phase 7: SDK, Worker, and Lazy-Loading Integration

Status: **partially complete; worker/artifact integration is active. Fixed
presign promotion and true online-only pool-hit loading remain in Local Phases
A through C**

This phase waits for the overlapping Phase 14B naming and strict Router A/B SDK
boundaries to stabilize. Earlier work remains inside isolated Rust crates,
Wasm wrappers, fixtures, and measurement tools.

### Historical implementation ledger

- Replace `eth-signer.worker.ts` with responsibility-specific worker entry
      points and discriminated request/result unions.
- Replace `ecdsa-hss-client.worker.ts` with three exact Client owners:
      `ecdsa-derivation-client.worker.ts`, `ecdsa-presign-client.worker.ts`, and
      `ecdsa-online-client.worker.ts`.
- Give each replacement one discriminated request/result union, one lazy
      Wasm loader, one secret-material/session owner, and no imports from either
      sibling worker's Rust/Wasm package.
- Remove static imports of the threshold-presign Wasm from passkey
      confirmation, general transaction encoding, role-local derivation,
      recovery, and export paths that do not fill a pool.
- Add operation-lazy dynamic imports with one typed loader per artifact.
- Preload/refill the presign engine only from explicit pool policy with
      observable reason, timing, result, and resource metrics.
- Require an active authenticated Client participant for every refill that
      creates usable Client/SigningWorker presignature pairs. Reject server-only
      promotion into the usable pool.
- Enforce one in-flight refill per exact pool owner or the separately
      reviewed bounded concurrency limit; deduplicate repeated low-water
      triggers.
- Ensure pool-hit normal signing cannot trigger a hidden presign import.
- Wire the SigningWorker to its fixed presign role and small online
      finalizer without introducing a generic service.
- Update build paths, asset manifests, cache policy, service-worker/static
      routes, server copy scripts, package files, integrity digests, and
      deployment bundles for the new artifact names.
- Ensure same URL/digest instances share browser cache where appropriate;
      record per-Worker instantiation memory separately.
- Add source and final-bundle guards for opposite-role or unrelated
      protocol symbols.
- Run the real registration, activation, pool fill, normal sign, recovery,
      refresh, add-signer, and export lifecycles through strict Router A/B.
- Execute every step in the Phase 7 local integration order and attach the
      immutable integration-bundle digest plus a zero-old-caller report.

### Exit Gate

- Browser waterfalls match the allowed artifact matrix for every ECDSA
      lifecycle.
- Pool-hit normal signing loads only the online leaf and required public
      transaction codec.
- Server bundles contain no Client state-opening implementation.
- No caller imports the mixed `eth_signer` package.

## Phase 8: Security, Formal, and Performance Gates

Status: **partially complete for the integrated derivation and online Client
path; purpose-built fixed-backend assurance remains Local Phase D and deployed
measurements are deferred**

### Formal and anti-drift TODO

- Complete the Phase 4 Verus-first scaffolds in
      `router-ab-ecdsa-presign/formal-verification` and
      `router-ab-ecdsa-online/formal-verification`. Each contains a pinned
      toolchain, proof inventory, assumption ledger, fixtures, model, and
      executable anti-drift suite.
- Preserve valid role-local derivation proofs by moving them from the old
      ECDSA-HSS owner into `router-ab-ecdsa-derivation/formal-verification`.
      Those proofs make no claim about the new signing protocol.
- Prove fixed Client/SigningWorker identities, participant ordering,
      two-party Lagrange coefficients, canonical scalar domains, registered
      share-commitment addition, and wallet public-key equality.
- Specify the fixed two-party additive-share and Lagrange relations,
      rerandomization equations, share combination, low-`s` normalization, and
      accepted final-signature relation.
- Prove the online role functions preserve the specified relation under
      canonical valid inputs.
- Model exhaustive presign role states, exact message admissibility,
      matched-pair commitment, monotonic reserve/commit/destroy, retry
      idempotence, and
      rejection of replay, reflection, reorder, and cross-context messages.
- Add executable production-to-model anti-drift tests over the frozen
      secp256k1 corpus and every reachable state transition.
- Run four differential modes while the oracle wire harness exists: NEAR
      with NEAR, purpose-built Client with NEAR SigningWorker, NEAR Client with
      purpose-built SigningWorker, and purpose-built with purpose-built. After
      the compact wire cutover, compare normalized semantic events, equations,
      outputs, and aborts rather than obsolete MessagePack bytes.
- Require deterministic randomness only inside the oracle harness so each
      differential case can reproduce coins and transcript values. Add a
      release guard proving the deterministic provider is unreachable.
- Record Aeneas/Lean boundary extraction as deferred. Promote a specific
      proof only when a later risk decision identifies a material claim that
      the Verus implementation proofs and executable anti-drift suite cannot
      cover.
- Add `just router-ab-ecdsa-fv`,
      `just router-ab-ecdsa-oracle-parity`, and
      `just router-ab-ecdsa-constant-time` gates with exact-count checks so an
      empty or partially skipped suite fails CI.
- Add an exact-count API parity gate that compiles the positive downstream
      Rust and TypeScript fixtures, compares generated Wasm/TypeScript
      declarations with the approved manifests, and proves excluded generic
      and invalid lifecycle calls still fail to compile.
- Keep cryptographic hardness, RNG quality, OT security, erasure, and
      production constant-time claims in an explicit assumption ledger until
      separate evidence closes them.

### Security TODO

- Run constant-time source and compiled-output review for secret scalars,
      OT choices, triple shares, presignature shares, rerandomization values,
      and online signature shares.
- Inspect exact release native and Wasm output, plus representative O0/O3
      and x86_64/arm64 builds where those targets ship, for secret-dependent
      branches, memory indexes, division/remainder, indirect calls, early-exit
      comparisons, and variable-length encodings. Trace every finding to
      secret or public inputs and record the disposition.
- Fuzz every public Wasm, peer-message, persistence, and Router envelope
      parser.
- Test malformed/noncanonical SEC1 points, zero/out-of-range scalars,
      invalid proofs, wrong challenges, replay, reflection, reordering,
      truncation, extension, duplicate consume, crash recovery, and rollback.
- Verify zeroization and secret-free errors/logs for success, recoverable
      abort, timeout, and pool eviction. Verify that traps, `panic=abort`, and
      Worker termination destroy the isolated memory and leave no controllable
      JavaScript copies; record platform-owned copy limitations explicitly.
- Complete dependency/license review for the dev/test-only pinned NEAR
      oracle and the independently owned production implementation.
- Complete a bounded independent review of the fixed-path critical-check
      matrix, deliberate NEAR divergences, four-case oracle results,
      Verus obligations, constant-time findings, and transcript/state/codec
      changes.

### Performance TODO

- Re-run raw/gzip/Brotli and full-distribution accounting from a clean
      locked checkout.
- Capture browser and Cloudflare-compatible p50/p95/p99 for every target
      lifecycle, separating download, parse, compile, instantiate, protocol,
      Router, persistence, and SigningWorker time.
- Record pool generation throughput, target depth, refill trigger, burn
      behavior, exhaustion frequency, and cost per usable presignature.
- Record peak and retained memory per browser Worker and server role.
- Compare all results with the Phase 0 baseline and the frozen
      purpose-built budgets.

### Exit Gate

- Formal and executable anti-drift gates pass for the purpose-built online
      and presign implementations.
- The four-case source/role-replay/new-new oracle matrix passes, and release
      guards prove the oracle, deterministic RNG, and alternate transcript
      profiles are absent from production artifacts.
- Every selected security claim has corresponding evidence; all remaining
      assumptions and exclusions are explicit.
- Size, total-distribution, latency, memory, pool-throughput, and cost
      budgets pass.
- The bounded 80/20 review approves the critical-check matrix,
      differential evidence, Verus obligations, recorded divergences, and hard
      cutover under the explicit assumption ledger.

## Phase 9: Hard Cutover and Deletion

Status: **partially complete; mixed artifacts, workers, HSS terminology, and
generic service ownership are deleted. The last generic presign/finalization
backend is deleted in Local Phase E**

### Historical implementation ledger

- Delete `wasm/eth_signer`, its generated package, mixed Worker loader,
      build paths, copied assets, package metadata, smoke fixtures, and bundle
      labels.
- Delete `signer-core::threshold_ecdsa` after its current functions move to
      the purpose-built presign and online owners.
- Remove the broad `threshold-ecdsa` and `threshold-ecdsa-hss` feature
      closures as coordinated with Phase 14B.
- Delete every production dependency on the monolithic NEAR crate. Retain
      the exact pin only in the dev/test oracle harness.
- Delete old generic constructors accepting participant vectors, runtime
      participant IDs, and thresholds.
- Delete server functions from browser bindings and client functions from
      SigningWorker bindings.
- Destroy obsolete development presignature pools and delete their record
      decoders, migration fixtures, and compatibility tests.
- Delete tests, snapshots, mocks, benchmarks, and guards that protect the
      mixed artifact or obsolete protocol behavior.
- Complete Phase 14B's ECDSA-HSS rename with no aliases, deprecated symbols,
      compatibility loaders, or old protocol identifiers.
- Move valid derivation formal assets to their new owner and delete the old
      `ecdsa-hss` formal directories, commands, fixtures, and signing claims.
- Complete the strict Router A/B migration and delete
      `ThresholdSigningService`; this refactor creates no successor service.
- Add repository guards for the deleted package, exports, feature names,
      old worker imports, old asset filenames, and forbidden dependency edges.
- Update architecture, deployment, capability, formal-verification,
      operations, incident, pool-management, and size-budget documentation.
- Execute the coordinated deployment order and retain receipts for
      admission closure/reopening, old-pool destruction, initial new-pool fill,
      artifact digests, and the verified signature.
- Close every Cleanup and Deletion Ledger row with replacement evidence
      and passing deleted-symbol guards.

### Exit Gate

- Repository search finds no production `eth_signer`, ECDSA-HSS,
      `ThresholdSigningService`, mixed-artifact export, or generic threshold
      constructor.
- Each browser/server artifact contains only its documented role and
      lifecycle code.
- Pool-hit normal signing uses the small online path and zero Deriver calls.
- Public-key, address, signing, recovery, refresh, and export parity pass.
- Clean-build size, waterfall, latency, memory, pool, constant-time,
      formal, and strict Router A/B gates pass.
- The purpose-built fixed 2-of-2 threshold-ECDSA presign backend is the sole
      production implementation.

## Dependency and Export Guard Matrix

| Artifact | Required | Rejected |
| --- | --- | --- |
| Role-local ECDSA client | threshold-PRF output opening, `k256`, HPKE/state/export primitives | threshold signing, OT, triples, presign driver, SigningWorker APIs |
| Online ECDSA client | `k256`, fixed online equations, client presign record opening | NEAR threshold crate, `rmp-serde`, `futures`, server finalizer, Derivers |
| Presign ECDSA client | fixed Client OT/presign role and bounded wire | NEAR threshold crate, `rmp-serde`, `futures`, server role, derivation, P-256, EIP-1559, local full-key signing |
| SigningWorker presign | fixed server OT/presign role, server persistence boundary | NEAR threshold crate, `rmp-serde`, `futures`, client material opening, Deriver roots, browser bindings |
| SigningWorker online | server presign opening, share combine, verification, monotonic reserve/commit/destroy | OT when pool hit, Derivers, client state |
| EVM codec | public transaction hash/encoding | secret shares, presign, P-256 |
| WebAuthn P-256 | P-256 and strict COSE parsing | secp256k1 threshold signing, EVM transaction logic |

Guards inspect Cargo features and dependencies, source imports, Wasm names and
exports from an unstripped analysis build, generated TypeScript declarations,
JavaScript chunks, copied static assets, and final Cloudflare/browser bundles.
Release stripping cannot conceal a forbidden dependency from the analysis
gate.

## Risk Register

| Risk | Tripwire | Response |
| --- | --- | --- |
| Metadata stripping breaks bindings or diagnostics | export/runtime parity fails or release cannot be symbolized | stop Phase 1; fix post-bindgen ordering and private digest mapping |
| Artifact split increases total SDK size | unique gzip/Brotli assets exceed Phase 0 total budget | merge only measured leafs with identical loading lifecycles or reduce duplicated dependencies |
| Lazy loading causes user-visible pool misses | pool-miss rate or p95/p99 exceeds budget | tune bounded proactive refill/preload and pool depth; preserve observable failure |
| Refill is incorrectly treated as server-only work | a usable presignature appears without an authenticated participating Client transcript | stop issuance, destroy affected material, and correct the role/state boundary |
| Background refill enables cost or storage exhaustion | wallet/user/tenant/global refill or burn budget is exceeded | throttle admission, stop refill, expire abandoned material, and alert operations |
| Online rewrite changes signature behavior | any share, signature, recovery-ID, or verification differential | stop integration and correct the isolated online kernel |
| Purpose-built implementation drifts from the oracle | transcript, message, proof, equation, output, or abort differential | stop promotion and correct the isolated implementation |
| Specialization silently removes a security check | construction check inventory lacks a mapped implementation or reviewed unreachability argument | stop implementation and restore the check or complete the reviewed argument |
| Behavioral parity is used to claim construction security | release claim has no reviewed adversary model, proof reference, or assumption ledger entry | block promotion and narrow the claim until independent review closes it |
| Ambiguous delivery or rollback revives one-use material | either role returns a reserved/committed pair to `available` or signs twice with one pair ID | close admission, destroy the affected generation, investigate exposure, and correct monotonic state handling |
| Fixed specialization weakens proof assumptions | independent review rejects equivalence or role constraints | stop promotion and revise the specification or implementation |
| Codec change alters commitment/challenge semantics | independent transcript reproduction or adversarial corpus fails | stop promotion and correct the canonical specification and codec |
| Split artifacts expose opposite-role APIs | dependency/export/final-bundle guard fails | stop release and remove the forbidden edge/export |
| Presign cutover revives or mixes old material | old record accepted or mixed protocol ID consumes | stop pool issuance, destroy obsolete pools, and require the new exact record kind |
| NEAR oracle leaks into production | release dependency, source, symbol, or bundle guard finds the oracle crate | stop release and remove the production edge |
| Size work regresses constant-time behavior | compiled review finds secret-derived control or memory access | reject the optimization or replace it with a reviewed constant-time construction |

## Validation Strategy

Validation matches change risk:

- Phase 1 runs focused Wasm build, binding, Node, browser Worker, and
  Cloudflare-compatible smoke tests plus byte reports.
- Phases 2 and 3 run focused crate/Wasm tests, dependency/export guards,
  differential online vectors, bundle accounting, and targeted ECDSA worker
  tests.
- Phases 5 and 6 run the complete fixed-path deterministic and randomized
  two-party differential corpus, parser fuzzing, adversarial protocol tests,
  constant-time review, and bounded critical-check review.
- Phase 7 runs strict Router A/B local smoke tests and the real intended ECDSA
  registration, signing, recovery, refresh, and export contracts.
- Phases 8 and 9 run clean release builds, final bundle scans, complete ECDSA
  lifecycle tests, formal/anti-drift gates, and the broad security-sensitive
  suite required by the public API and build-system changes.

Every size report records tool versions and exact artifact digests. Comparisons
use the same compressor and settings. A reduction in one file cannot claim
success when the operation waterfall, unique distribution total, initialization
latency, retained memory, or pool cost regresses beyond its gate.

## Completion Checklist

- Production Wasm metadata is stripped and private symbol evidence is
      reproducible.
- Role-local derivation, presigning, online signing, EVM codecs, and P-256
      utilities have explicit owners.
- Normal pool-hit signing loads no presign engine and calls no Deriver.
- Browser artifacts contain no SigningWorker implementation.
- Online signing contains no NEAR threshold crate, MessagePack, futures,
      OT, or triples.
- Phase 4 freezes the purpose-built specification and dev/test-only NEAR
      oracle boundary.
- The purpose-built implementation has no production NEAR dependency and
      passes the fixed-path oracle, provenance, API-surface, and bounded-review
      gates.
- Size, total distribution, waterfall, latency, memory, pool, and cost gates
      pass.
- Public-key, address, signature, recovery-ID, recovery, refresh, and export
      parity pass.
- Formal anti-drift and constant-time evidence covers the purpose-built
      online and presign kernels.
- Verus proves the approved high-leverage algebra and monotonic lifecycle
      properties; deferred proof systems remain explicit non-claims rather
      than release gates.
- The construction-level check inventory has no unexplained deletion, and
      the reviewed adversary/assumption ledger matches the released protocol.
- Monotonic reserve/commit/destroy, matched-pair commitment, registry binding,
      transcript binding, fresh entropy, retry, rollback, and stale-state
      invariants pass adversarial and crash tests.
- The mixed `eth_signer`, obsolete features, old generated assets, stale
      pools, obsolete codecs, fixtures, and tests are deleted.
- The coordinated switchover receipt proves no mixed Client, Router,
      SigningWorker, codec, persistence, or asset release was admitted.
- Every Cleanup and Deletion Ledger row is closed and deleted-symbol guards
      reject the obsolete paths outside their narrow historical/oracle
      allowlists.
- Strict Router A/B is the sole ECDSA lifecycle architecture.

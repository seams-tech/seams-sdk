# Yao A/B Deployment and Production Release Plan

Status: **Cloudflare deployment active; same-account benchmark deployed**

This file owns deployment, production security-profile selection, deployed
benchmarking, production promotion, release validation, external review, and
burn-in tasks moved from [yaos-ab.md](./yaos-ab.md). Phase identifiers remain
stable. The active local implementation and cleanup queue stays in
[yaos-ab.md](./yaos-ab.md).

No unchecked task in this file blocks the local Yaos-AB checkpoint.



## Phase 9D: Run the Cloudflare Topology Campaign

Status: **same-account deployment complete; two-account campaign pending**

Goal: deploy the locally proven flow without changing its cryptographic or
lifecycle behavior, establish the same-account lower bound, measure the
intended separate-account topology, and supply the Phase 13A go/no-go evidence.

Same-account deployment checkpoint (2026-07-16):

- endpoint: `https://yaos-ab-benchmark.seams.sh/benchmark/activation`;
- Deriver A version: `97aa6e79-4ab3-4a23-9c3f-0a68a0ecb134`;
- Deriver B version: `b3940de8-1162-4221-80a6-7639a01ba515`;
- deployment identity: `23e830706f862fe346b8c238bd8a4eb9`;
- two live protocol smoke requests passed. The warm request completed in
  252 ms of Worker protocol time; B's first response byte reached A at 12 ms,
  before A closed its request direction at 241 ms.

#### TODO

- [ ] Re-run `validate:yaos-ab-local` and `validate:local-readiness`, then bind
      both exact evidence bundles into the deployment receipt before upload.
- [x] Deploy the fixed one-account artifacts and prove B's `Offer` reaches A
      before A closes its request.
- [ ] Deploy the fixed two-account artifacts and prove the same early-response
      property over cross-account HTTPS. Measure authentication overhead as a
      separate experiment without freezing production trust policy.
- [ ] If cross-account HTTP streaming fails, test one WebSocket fallback with
      typed `TableEnd`, `AControlEnd`, and `BControlEnd` markers, post-end
      rejection, and binary frames. Retain only the selected transport.
- [ ] Record warm p50/p95/p99 and the 20-deployment fresh-version first-request
      operational cold proxy for both account modes.
- [ ] Record A/B CPU, P50/P90/P99/P999 reservoir-sampled shared-isolate memory,
      `exceededMemory`, requests, exact bytes, OT rounds, frame timing,
      scheduling overlap, and complete response-EOF wall latency.
- [ ] Record placement and connection reuse for intended client regions,
      including A/B `cf.colo` where available.
- [ ] Estimate Cloudflare request and CPU cost per million complete local
      lifecycles. Record the applicable Workers bandwidth pricing separately.
- [ ] Run the retained fault, receipt, source/build-input, constant-time,
      account-commitment, cold-cohort, analytics, cost, and cleanup checks
      against the exact deployed versions.

#### Phase 9D Exit Gate

- [ ] The complete Phase 9C lifecycle runs unchanged in both Cloudflare account
      profiles.
- [ ] Both roles have reservoir-sampled shared-isolate P999 below 96 MiB and
      zero observed `exceededMemory`; exact physical peak remains unproven.
- [ ] Separate-account evidence measures the intended topology without
      claiming production authentication, active security, durability, or
      release readiness.
- [ ] Warm, cold-proxy, CPU, memory, bytes, placement, connection, and cost
      evidence is complete, receipt-bound, and accepted by the Phase 13A
      evaluator.

## Phase 13A: Viability Go/No-Go

Status: **blocked on Phase 9D deployed evidence; once that evidence exists,
this is the only gate that may open profile selection and productionization
work**

Goal: decide whether the locally usable Streaming Yao lifecycle is worth
production investment after running its unchanged Yao-bearing flows in the
intended topology.

### Local Preflight

- [x] Require the exact passing Phase 9C `validate:yaos-ab-local` evidence
      bundle, complete lifecycle vector set, key-export continuity result, and
      zero-Deriver ordinary-signing trace. The gate deletes any previous
      receipt before execution and publishes a new mode-0600 receipt only after
      all nine SDK, Rust/WASM, process, source-isolation, and constant-time
      subgates pass. Both fixed profiles commit registration, activation,
      recovery, refresh, exact export, and post-refresh ordinary-signing
      evidence. Phase 13A recomputes the 2,238-file local source/build-input
      digest and rejects missing profiles or vectors, key substitution,
      continuity/signature failure, nonzero signing-path Deriver calls or
      bytes, stale source inputs, lifecycle-report drift, and omission of the
      exact Yao TypeScript subgate. The July 14, 2026 receipt covers 2,200
      files and 35,759,080 bytes with source/build-input digest
      `ab8b0530cb30e8863759d32a3d907037e03934b3f30dec2ab6b8e278c1fca76c`.

- [x] Pin the Phase 3, Phase 4, Phase 5, Phase 9B local report, stream KAT JSON
      and binary, Worker manifest, and isolation source guards by SHA-256 in a
      canonical local evidence bundle.
- [x] Verify the committed activation/export stream KATs against their pinned
      artifact and require `table_bytes = 32 * and_gate_count`. The activation
      table is exactly 2,104,960 bytes for 65,780 AND gates.
- [x] Verify the 51-sample local-workerd baseline has zero failures and remains
      below the provisional ceremony limits after the raw secret-ingress
      refactor: p95 147.640 ms and p99 149.819 ms. These values are local
      lower-bound evidence.
- [x] Add `npm run phase13a:local-preflight` and mutation fixtures. The only
      successful local status is `deployment-required`; the evaluator keeps
      `phase13a_decision = unavailable`, `production_eligible = false`, and all
      eleven deployed evidence classes mandatory. Its 13 local checks now
      include the fresh Phase 9C receipt, with mutations covering gate failure,
      profile/vector deletion, export-key and signature substitution, nonzero
      signing-path Deriver traffic, and source-tree drift.
- [x] Rerun the underlying passive core rather than relying only on pinned
      reports: 99 Rust tests including two real A/B processes, three strict
      core/WASM Clippy targets, the independently regenerated Phase 5 stream
      KAT, 186 independent Python verifier tests, and 128 freshly generated
      differential cases pass. Stale unused accessors/session fields and the
      verifier evidence-count/lockfile drift found by this gate were removed.
- [x] Run the fail-closed formal parity gate inside local readiness: 80
      production Rust tests, 418 generator Rust tests including 25 circuit
      tests, and three artifact-filesystem-policy tests pass with exact pinned
      counts.
- [x] Rebuild and execute all six Phase 5 WHATWG-stream WASM profiles in normal
      and independently delayed producer/consumer modes. Exact table bytes,
      frame counts, bounded buffers, zero runtime host-boundary copies,
      transcript completion, and producer/consumer suspension all pass.
- [x] Bind a typed activation/128-KiB wire ledger to both Worker roles and the
      Phase 13A preflight. It records 2,104,960 table bytes, 82,112 ordinary
      passive-OT bytes, 33,300 other control bytes, 400 envelope-header bytes,
      and 2,222,584 total A/B transport bytes. Directional counter drift aborts
      with `YAOS_AB_WIRE_ACCOUNTING`.
- [x] Record a current 21-sample local native and Node WASM compute/memory
      baseline for activation and export at 128 KiB. Activation native p95 is
      68.026 ms wall and 80 ms combined process CPU; Node WASM p95 is 132.156
      ms wall and 130.052 ms combined role-synchronous time. Native role RSS
      stays below 5.3 MiB and WASM linear memory reaches 4,390,912 bytes. These
      are explicitly local lower bounds.
- [x] Add a fail-closed production-reachability audit with mutation fixtures
      and pin its report in the local preflight. The audited tree has four
      exact development/verifier core dependents, zero benchmark-crate
      dependents, zero references across 5,743 product files, 19 explicitly
      non-production Wrangler configurations, and zero production routes.
- [x] Freeze the deployed evidence-integrity contract locally. The evaluator
      recomputes warm and fresh-version first-request quantiles, rejects reused
      deployment/version identities and artifact drift, recomputes the complete
      per-million cost model, and requires a project-owned operational ceiling
      plus independent-account acceptance before it can emit `go`.

#### TODO

- [x] Require all gate KATs, complete activation/export differential vectors,
      and separate-process A/B correctness tests to pass.
- [x] Record actual garbled-table and OT/control bytes; require the table bytes
      to equal `32 * and_gate_count` with no JSON or base64 representation.
- [x] Record native and local WASM garbling/evaluation compute and peak-memory
      evidence.
- [ ] Record deployed Worker garbling/evaluation CPU and reservoir-sampled
      shared-isolate memory percentiles for both account modes.
- [ ] Record same-account and separate-account Cloudflare warm p50/p95/p99 and
      fresh-version first-request proxy p50/p95/p99, first/final-byte timing,
      request count, placement, and failures.
- [x] Record local total wall latency for the complete passive ceremony,
      including fresh ordinary passive OT, OS-random sessions, private output
      coins, streaming, transcript completion, and recipient artifacts. Native
      activation p95 is 68.026 ms and local-workerd client p95 is 147.640 ms.
- [ ] Record deployed total wall latency for that same complete passive
      ceremony in both account modes.
- [ ] Estimate Cloudflare request and CPU cost per million ceremonies from the
      measured implementation.
- [x] Confirm no Router, SDK, SigningWorker, Durable Object, production route,
      or caller can reach the benchmark protocol.
- [ ] Publish one dated decision: `go`, `stop`, or one explicitly bounded
      platform-rung experiment.

#### Go criteria

- [x] Every committed and randomized correctness case passes locally.
- [x] Semi-honest fixed-circuit tables are at most 2.10 MiB; the activation
      table is 2,104,960 bytes (2.008 MiB).
- [ ] Cross-account 2.10 MiB transfer p95 is below 75 ms.
- [ ] Complete passive ceremony p95 is at most 250 ms and p99 is at most 500 ms.
- [ ] Combined A+B CPU is at most 150 ms at p95.
- [ ] Every A/B role in both topologies has reservoir-sampled shared-isolate
      P999 below 96 MiB and zero observed `exceededMemory`, with exact peak
      explicitly unproven.
- [ ] The estimated cost and independent-account topology are operationally
      acceptable.

A `stop` ends Yao implementation after the local proof-of-usability and before
production hardening, deep formal proof, external review, durable lifecycle,
production integration, or cleanup. A `go` opens Phase 6A.
Missing, malformed, or statistically insufficient evidence yields
`evidence-incomplete`. This state is neither a `go` nor the substantive `stop`
decision reserved for complete evidence that fails a viability criterion.

## Phase 6A: Select the Security Profile and Reissue Feasibility Gates

Status: **deferred until Phase 13A records a viability `go`; candidate research
must not interrupt the benchmark critical path**

Goal: use measured passive-kernel, complete-circuit, streaming, and Cloudflare
evidence to select the strongest coherent security profile meeting the online-
latency SLO, then freeze its implementation, platform, lifecycle, exact claim,
and release budgets before production hardening.

This phase consumes the surviving benchmark implementation. It does not own the
first gate kernel, complete-circuit runtime, stream, or Cloudflare measurements.
P0 becomes production-eligible only through this phase's signed decision and
the remaining release gates.

### TODO

- [ ] Write the construction and composition map for malicious OT, garbling
      correctness, input consistency, private randomized output, provenance,
      active-output binding, selective failure, and uniform abort.
- [ ] Freeze the P0 operational hardening bundle, passive-corruption model,
      honest-execution assumptions, excluded active attacks, and mandatory
      release evidence.
- [ ] Import the measured Phase 13A P0 baseline; rerun only experiments needed
      to resolve a concrete profile-selection question.
- [ ] Evaluate the bounded candidate set in this document: WRK17/KRRW18
      authenticated garbling, SoftSpoken/KOS/Ferret-family OT choices, and
      Lindell-style or batched cut-and-choose.
- [ ] Group candidates into coherent P1, P2, and P3 profiles with an exact claim
      for each complete composition; reject feature lists without a reviewed
      composition argument.
- [ ] Record dual execution as disqualified because adversarial leakage
      compounds across aborts and retries involving long-lived inputs.
- [ ] Freeze the selected profile, compiler, OT suite, input-provenance scope,
      randomized-output realization, output-authentication scope, garbling
      hash, and residual exclusions.
- [ ] Decide whether to promote and harden the exact Phase 3 benchmark garbling
      hash or delete/replace it with a reviewed alternative; record the measured
      latency delta and composition rationale.
- [ ] Compare porting and hardening Swanky, mpz, or EMP components against a
      repository implementation; record license, maintenance, dependency,
      audit, WASM/native, and effort consequences.
- [ ] Obtain approval for a concrete implementation and review effort budget.
- [ ] Derive selected-profile online and offline bytes, preprocessing storage,
      rounds, request graph, CPU, peak memory, retained state, and disposal
      points from measured Phase 13A evidence plus narrow candidate experiments.
- [ ] Publish the exact lifecycle transaction/write graph and identify which
      A/B operations can safely overlap or coalesce.
- [ ] Freeze `EpochFloorAuthorityV1` and the circuit-version drain/destroy
      policy as construction inputs to Phase 7.
- [ ] Select the preferred feasible platform from the fallback ladder and
      record the tripwire that activates each lower rung.
- [ ] Reissue the Phase 13B construction-specific payload, round, latency, CPU,
      memory, storage, and cost objectives before production hardening begins.
- [ ] Freeze the maximum permitted absolute and percentage p95/p99 latency
      increase over P0 and apply it before comparing total cost.
- [ ] Select the strongest profile that meets the reissued SLO; record every
      stronger rejected profile and its measured latency tripwire.
- [ ] Align `router-a-b-sol-refactor.md`, `router-a-b-SPEC.md`, the deployment
      specification, and the formal-verification plan with the selected claim
      before Phase 6B closes.
- [ ] Produce a signed Phase 6A construction decision record with the named
      cryptographic, constant-time, deployment, and performance reviewers.

### Kill Criteria

Phase 6A rejects a candidate, lowers the security profile, changes platform, or
stops when one of these conditions holds:

- its stated proof omits an attack claimed by that profile, leaks beyond its
  explicit exclusions, or fails the long-lived-input retry model;
- no reviewable build-or-port path fits the approved effort budget;
- the Worker garbling primitive fails compiled constant-time review;
- projected payload, rounds, CPU, memory, or Durable Object critical-path
  latency exceeds the reissued budget;
- the implementation cannot preserve independent administrative domains;
- an independent reviewer rejects the assumptions or composition.

P2/P3 failure moves to a coherent P1 candidate and then P0. Platform evaluation
uses Workers, then Containers, then independently administered native services.
P0 failure on mandatory controls, correctness, privacy under honest execution,
constant-time review, independent administration, or the latency SLO stops the
protocol.

### Exit Gate

- [ ] The signed decision record freezes one P0-P3 profile, one platform,
      every construction and composition choice, the exact corruption claim,
      and every exclusion.
- [ ] Measured Phase 13A evidence plus candidate-specific experiments account
      for all online and offline bytes, rounds, CPU, memory, storage, and state
      retention.
- [ ] The reissued Phase 13B budget table identifies hard platform limits,
      provisional product objectives, and candidate-specific thresholds.
- [ ] The selected implementation path fits an approved effort and review
      budget.
- [ ] The selected platform profile preserves two independent administrators
      and has a reviewed constant-time strategy.
- [ ] The selected profile meets the absolute and incremental p95/p99 SLO
      against the measured P0 baseline.
- [ ] Capability, Router, deployment, and formal plans match the selected claim
      and contain no stronger residual wording.
- [ ] Every kill criterion has evidence-backed disposition and no unresolved
      critical or high finding remains.

## Phase 6B: Implement the Selected Suite and Freeze Production Circuits

Status: **blocked on the Phase 13A viability `go` and Phase 6A selection**

Goal: implement the exact Phase 6A profile and produce the only artifacts and
entrypoint eligible for production.

### TODO

- [ ] Implement every mandatory 80/20 control and the selected P0-P3 protocol
      composition without dormant security-profile branches.
- [ ] Instantiate every Phase 1 opaque provenance/evidence slot with the
      Phase 6A-selected authenticated root record, custody boundary, input
      binding, and verification mechanism.
- [ ] Implement the selected registration input-selection realization and its
      retry/acceptance state machine without widening the approved claim.
- [ ] Implement the selected joint refresh-delta generation, output binding,
      abort-equivalence, and minimum durable-lifecycle realization against the
      construction-independent Phase 1 relations.
- [ ] For P0, implement ordinary reviewed OT, fresh per-ceremony labels and
      randomness, pinned artifacts, authenticated transcripts, strict framing,
      replay controls, recipient encryption, and public output checks.
- [ ] For P1-P3, implement only the Phase 6A-selected malicious OT,
      garbler-correctness, input-consistency, selective-failure, provenance, and
      active-output mechanisms required by the approved composition.
- [ ] Prove randomized-output privacy and bias resistance to the extent claimed
      by the selected profile.
- [ ] Compose the selected input handling, garbling, randomized output,
      recipient authentication, and lifecycle-specific functionality in the
      final activation and export circuits/protocols.
- [ ] Define the selected output binding over decoded scalar, point, ciphertext
      digest, recipient, and transcript; distinguish P0 signed/public checks
      from P1-P3 active authentication.
- [ ] Implement the selected authenticated ciphertext opener, sealed opened-
      share construction, production wire/storage transactions, and runtime
      party-view/lifecycle corpus.
- [ ] Add scalar-share point commitments and the jointly signed public output
      receipt required by the selected profile.
- [ ] Enforce canonical Edwards encoding, identity/small-order/torsion
      rejection, prime-subgroup validation, and strict scalar-to-point
      equality at the selected production boundary.
- [ ] Add adversarial degenerate-seed, output replacement, correlated-delta,
      and self-consistent replacement tests for A and B.
- [ ] Add idempotent ciphertext redelivery with no reevaluation.
- [ ] Regenerate final production schedules, manifests, gate counts, byte
      counts, and circuit digests.
- [ ] Freeze every selected circuit-wire and production-artifact encoding in
      the normative corpus and add generated-spec drift checks.
- [ ] Embed only those production artifacts in `crates/ed25519-yao`.
- [ ] Scan the selected production dependency graphs and runtime bundles for the
      clear evaluator, reference oracle, and generator.
- [ ] Make abort messages uniform and transcript-verifiable.
- [ ] Add corrupt-A and corrupt-B protocol harnesses.
- [ ] Add wrong-circuit, wrong-input, malformed-OT, selective-failure,
      inconsistent-output, and early-abort tests.
- [ ] Delete losing P0-P3 prototypes, inactive hardening paths, and unused
      dependencies.
- [ ] Establish the external release authority outside GitHub: independently
      administer reproducer/reviewer keys, publish the pinned policy digest and
      approval-sequence floor, issue one-use reproduction challenges, and
      publish accepted commit identities through an immutable channel.
- [ ] Independently reproduce the complete selected candidate on a clean host,
      obtain separate cryptographic-reviewer approval, and run the independent
      release verifier against exact `E` plus the external policy and challenge.
- [ ] Require fresh reproduction and reviewer approval after every covered
      compiler, artifact, schema, digest, schedule, metric, corpus,
      specification, policy, verifier, or change-control change.
- [ ] Obtain independent design review before product composition.

### Exit Gate

- [ ] The implementation satisfies the exact Phase 6A corruption and
      correctness claim; P2/P3 require a valid committed result or detectable
      abort from one malicious Deriver.
- [ ] The honest role's input and recipient outputs remain private under the
      selected profile's corruption model.
- [ ] The implemented proof claim matches the approved construction exactly.
- [ ] Selected-profile online/offline bytes, rounds, CPU, and memory are
      recorded against P0.
- [ ] Input-provenance setup, proof bytes, rounds, and verification CPU are
      recorded separately.
- [ ] Production circuit and security-suite digests reproduce across clean
      builds and are distinct from benchmark-only artifact IDs.
- [ ] No critical or high cryptographic review finding remains.

## Phase 7: Add the Selected One-Use Lifecycle and Optional Prepositioning

Status: **blocked on Phases 5 and 6B**

Goal: enforce the selected profile's minimum safe one-use/session lifecycle and
move work offline only when the measured latency benefit exceeds persistence
and tail-latency cost.

P0 just-in-time execution uses fresh labels, OT state, randomness, nonces, and
session domains plus replay and output-commit records. It does not inherit a
preprocessing pool, base-OT reuse, distributed ticket states, or Durable Object
round trips that its reviewed passive construction does not require. P1-P3 add
only the lifecycle states required by their selected preprocessing and active
security composition.

### Common TODO

- [ ] Freeze the minimal P0-P3 lifecycle selected by Phase 6A and make unused
      states, stores, pools, and transitions absent from production types.
- [ ] Generate fresh per-ceremony labels, OT state, garbling randomness, nonces,
      and session domains for every profile.
- [ ] Bind the selected circuit, security suite, wallet, request, roles,
      recipients, epochs, authorization, and transcript into replay and terminal
      records.
- [ ] Persist only the minimum selected state required for replay prevention,
      exact encrypted redelivery, rollback safety, and the approved claim.
- [ ] Implement the production durable adapter that atomically writes promoted
      state and retirement tombstones, binds the transaction-receipt digest,
      enforces rollback/replay floors, and survives every crash boundary.
- [ ] Freeze its durable-storage encoding and generated-spec drift guard.

### Conditional Preprocessing TODO

- [ ] Implement consuming ticket types and transition APIs.
- [ ] Implement paired public ticket commitments.
- [ ] Implement independent role-local generation counters.
- [ ] Implement the signed two-phase reservation handshake with locally atomic
      transitions.
- [ ] Add `Prepositioning`, `OutputPrepared`, and `OutputCommitted` state types.
- [ ] Reserve and activate before input-dependent release.
- [ ] Burn both sides after distributed reservation uncertainty.
- [ ] Add crash injection at every transition.
- [ ] Add concurrent reserve, double consume, rollback, restore, and retry tests.
- [ ] Encrypt persisted secrets under per-ticket keys.
- [ ] Destroy terminal per-ticket keys.
- [ ] Persist exact recipient ciphertexts and selected output bindings before
      output commit.
- [ ] Exchange both roles' signed package-digest set before local consumption.
- [ ] Release recipient packages only from consumed state.
- [ ] Rotate the base-OT channel epoch after restore, rollback, or counter
      uncertainty.
- [ ] Add peer-verifiable generation high-water marks.
- [ ] Implement `EpochFloorAuthorityV1` as an independently administered,
      append-only signed release ledger with offline roots and cross-account
      verification.
- [ ] Freeze the ticket lifecycle, epoch-floor authority, burn accounting, and
      circuit rollout in a versioned normative specification.
- [ ] Prove that restore, deployment rollback, and peer-key rotation cannot
      lower the accepted epoch floor.
- [ ] Implement per-wallet, per-organization, per-tenant, and global generation,
      activation, and burn budgets before ticket allocation.
- [ ] Attribute each burn reason and its CPU, storage, and preprocessing cost to
      the authenticated admission principal.
- [ ] Add a durable abuse circuit breaker that stops new preprocessing and
      ceremonies across isolates.
- [ ] Implement the circuit rollout rule: stop old issuance, destroy old
      pre-activation tickets, bound the activated drain set, and reject old
      digests for every new activation.
- [ ] Implement a shallow just-in-time OT pool only when the selected OT suite
      proves its reuse/domain rules and measurements justify the added state.
- [ ] Implement prepositioned garbled-circuit storage only for a selected
      profile whose proof permits it and whose online p95 improves materially.
- [ ] Stream stored chunks directly into B's evaluator.
- [ ] Add pool depth, expiry, burn rate, cleanup, and starvation metrics.
- [ ] Add storage and preprocessing cost to benchmark reports.

### Exit Gate

- [ ] No selected session or ticket material can be reused, cloned, rolled back,
      or returned to available.
- [ ] Backup restore cannot revive nonterminal material.
- [ ] Neither epoch-floor rollback nor circuit rollback can revive stale
      material.
- [ ] Burn caps and the global circuit breaker contain adversarial disconnect
      cost without weakening one-use semantics.
- [ ] A crash after output preparation permits exact ciphertext redelivery and
      no reevaluation.
- [ ] When prepositioning is selected, online output matches just-in-time output
      and online p95 improves without weakening the selected claim.
- [ ] P0 incurs no preprocessing or persistence transition absent from its
      reviewed minimum lifecycle.

## Phase 8: Promote Local Router Contracts and the Composition Adapter

Status: **blocked on Phases 6B and 7; Phase 9C is complete**

Goal: harden the exact Phase 9C contracts and composition adapter for the
Phase 6A-selected production claim while keeping crypto, lifecycle, and
transport ownership separate.

### TODO

- [ ] Import the exact Phase 9C control-plane schemas, builders, vectors, and
      adapter APIs without creating a parallel production shape.
- [ ] Instantiate every Phase 1 opaque evidence slot with the selected Phase 6B
      provenance, ciphertext, output-binding, receipt-signature, and
      authenticated-store artifacts.
- [ ] Add the Phase 7-selected durable session or ticket lifecycle and remove
      ephemeral local state from production admission.
- [ ] Bind authenticated domain records, authorization, immutable key-creation
      facts, protocol/circuit versions, deployment identity, recipient identity,
      and epoch floors at the production boundary.
- [ ] Add signed production manifests, terminal receipts, uniform errors, exact
      retry/redelivery rules, and canonical cross-language vectors.
- [ ] Replace local loopback transport policy with the selected direct
      production transport while preserving the same role-local adapter API.
- [ ] Delete local-only success shortcuts, synthetic authorities, permissive
      endpoint parsing, and any adapter state excluded by the selected profile.
- [ ] Retain compile/source guards against joined state, legacy backends,
      browser policy, Cloudflare policy in the core, and Deriver calls during
      ordinary signing.

### Exit Gate

- [ ] Invalid role, lifecycle, circuit, recipient, and ticket combinations fail
      at parsing or compilation.
- [ ] Core control-plane types contain no secret Yao payload.
- [ ] The production adapter is a strict hardening of the Phase 9C adapter and
      exposes no second lifecycle contract or runtime profile negotiation.
- [ ] Production core imports no Cloudflare or browser policy.

## Phase 10: Deploy the Selected Strict Production Profile

Status: **blocked on Phases 6A, 7, and 8**

Goal: run A and B under independent administrators on the Phase 6A-selected
production platform.

### TODO

- [ ] Freeze exactly one production security profile and one deployment profile
      from Phase 6A; exclude runtime negotiation, downgrade, and dormant
      production paths.
- [ ] Publish its administrator, identity, transport, placement, persistence,
      and review rules in a versioned deployment-profile specification.
- [ ] Provision distinct accounts or infrastructure domains, CI environments,
      deploy credentials, approvers, secrets, logs, storage, backups, and
      incident ownership.
- [ ] Add pinned peer endpoints and identities for A and B.
- [ ] Implement signed Router-to-A and Router-to-B cross-account dispatch.
- [ ] Implement signed ephemeral peer-session establishment.
- [ ] Implement direct A-to-B streaming HTTPS.
- [ ] Implement B-to-A OT/control HTTPS.
- [ ] Remove A-to-B Service Bindings and shared bearer credentials from every
      production profile.
- [ ] Implement signed A/B-to-Router recipient-package return.
- [ ] Implement Router-to-SigningWorker and SigningWorker-to-Router transport
      for the frozen account placement.
- [ ] Delete cross-account `.internal` URLs and Service Binding configurations
      from the Worker profile.
- [ ] Add administrative-domain and deploy-principal inequality checks, plus
      account-ID inequality checks for Cloudflare profiles.
- [ ] Add independent artifact and manifest signatures.
- [ ] Add negative cross-account deploy/storage access probes.
- [ ] Add rate, size, concurrency, timeout, and circuit-breaker controls.
- [ ] Connect admission to the Phase 7-selected session/ticket and burn budgets;
      record rejection or burn attribution by authenticated wallet,
      organization, and tenant.
- [ ] Verify epoch-floor and circuit-rollout enforcement across independent
      deployments and backups.
- [ ] For a Containers or native profile, repeat dependency, constant-time,
      compiled-output, erasure, placement, request, storage, and cost review;
      measure available CPU features instead of assuming AES acceleration.
- [ ] Measure placement and connection reuse across intended client regions.
- [ ] Add transcript correlation without secret logs.

### Exit Gate

- [ ] No credential can deploy or read both Derivers.
- [ ] Every cross-domain edge uses the frozen signed direct transport contract;
      a Worker deployment contains no cross-account `.internal` Service
      Binding URL.
- [ ] A and B execute the Phase 6A-selected protocol and exact claim over the
      selected direct transport.
- [ ] Router carries zero table bytes.
- [ ] Strict-profile latency, memory, CPU, storage, and byte measurements are
      recorded as Phase 13B inputs; Phase 13B applies the release thresholds
      after Phase 11.

## Phase 11: Promote Client and SigningWorker Lifecycles

Status: **blocked on Phases 8 and 10; Phase 9C is complete**

Goal: promote the already proven Phase 9C client and SigningWorker lifecycle to
the selected production security, transport, persistence, and release profile.

### TODO

- [ ] Reuse the Phase 9C client input, package-combine, identity-continuity,
      activation, signing, recovery, refresh, and export APIs unchanged.
- [ ] Replace local recipient protection and authorities with the Phase
      6A/6B-selected authenticated encryption, signatures, provenance, and
      output-binding verification.
- [ ] Connect the client and SigningWorker to Phase 7 durable retry,
      redelivery, burn, rollback, and epoch-floor enforcement.
- [ ] Deliver the selected jointly signed public output receipt to both
      recipients before either consumes its output.
- [ ] Expose the canonical `signer-core` client implementation through
      `wasm/near_signer` and remove local-only native entrypoints from the
      product path.
- [ ] Delete duplicated derivation, browser garbler/evaluator sessions,
      serialized HSS handles, and Ed25519-HSS callers after Phase 12 preserves
      valid ECDSA exports.
- [ ] Move the FROST verifying-share mapping into `signer-core` and verify
      `V_client = 2*X_client`, `V_server = -X_server`, and their sum.
- [ ] Repeat the Phase 9C end-to-end and negative suites against separately
      deployed production accounts, durable sessions or tickets, and exact
      idempotent ciphertext redelivery.
- [ ] Retain trace gates proving ordinary signing makes zero Deriver calls.

### Exit Gate

- [ ] Every Ed25519 lifecycle uses strict Router A/B.
- [ ] Exact seed export reproduces the registered Ed25519 key.
- [ ] Normal signing latency contains no Yao work.
- [ ] No product caller reaches the old HSS lifecycle.
- [ ] Product behavior matches the Phase 9C local lifecycle with only the
      selected production security, durability, and transport mechanisms added.

## Phase 13B: Full Release Validation

Status: **blocked on Phases 10 through 12**

Goal: validate the Phase 6A-selected and Phase 6B-hardened profile against its
exact security, correctness, memory, reliability, latency, and cost gates.

### Benchmark Matrix

- [ ] Import and reproduce the accepted Phase 13A passive baseline.
- [ ] Every coherent P1 targeted-hardening ceremony.
- [ ] P2 prepositioned full-active online ceremony.
- [ ] P3 just-in-time full-active ceremony.
- [ ] Every Phase 6A candidate and selected-platform profile needed to validate
      the signed decision record.
- [ ] Cold and warm runs.
- [ ] Intended client regions and recorded placement identifiers, including
      A/B `cf.colo` for Worker profiles.
- [ ] Preserve the dated HSS analytical estimates and existing simulator
      measurements as historical context; run no new HSS kernel or protocol.

Record:

- time to selected session activation or preprocessing-ticket reservation;
- input-provenance setup, proof bytes, rounds, proving CPU, and verification CPU;
- ordinary passive OT messages and sequential one-way rounds;
- time to first and final stream byte;
- garbling CPU;
- evaluation CPU;
- transcript and output time;
- total wall p50, p95, and p99;
- absolute and percentage p50/p95/p99 increase over P0;
- cold-start rate;
- A and B CPU-ms;
- A-to-B and B-to-A bytes;
- online and offline bytes;
- peak isolate/WASM memory and memory drift;
- enforced per-isolate admission cap and rejected-concurrency count;
- local-guard and durable-budget rejection latency and reason;
- selected session/ticket destruction and burn rate by wallet, organization,
  tenant, and global budget;
- CPU, storage, and preprocessing cost attributed to each burn reason and
  authenticated admission principal;
- storage reads, writes, and retained bytes;
- exact critical-path lifecycle transaction/write count plus p50, p95, and p99
  latency per transition;
- safe A/B overlap and same-role transition coalescing;
- requests per role;
- projected cost per million ceremonies.

### Performance Gates

The numeric payload, latency, and CPU values below begin as Phase 13A viability
objectives. Phase 6A may tighten or extend them through a signed, versioned
profile-and-platform SLO table, including the maximum permitted incremental
p95/p99 over P0, before Phase 6B begins. The selected platform's hard memory,
request-size, duration, and security limits remain binding.

- [ ] Publish and verify the Phase 6A-reissued values in the versioned release
      SLO specification.

- [ ] Semi-honest fixed-circuit tables are at most 2.10 MiB.
- [ ] Every selected-profile hardening and preprocessing cost is recorded
      without hidden offline bytes.
- [ ] Selected input-provenance setup, binding, proof, verification, and
      persistence costs are recorded without hidden provisioning work.
- [ ] Cross-account 2.10 MiB semi-honest control transfer p95 is below 75 ms, or
      prepositioned mode meets the full ceremony SLO.
- [ ] P0 establishes the canonical production-topology latency baseline.
- [ ] The selected production ceremony p95 is at most 250 ms and within the
      Phase 6A incremental budget over P0.
- [ ] The selected production ceremony p99 is at most 500 ms and within the
      Phase 6A incremental budget over P0.
- [ ] Combined A+B CPU is at most 150 ms at p95.
- [ ] Every selected Worker role has reservoir-sampled shared-isolate P999
      below 96 MiB and zero observed `exceededMemory`; exact peak remains
      unproven.
- [ ] Initial production enforces the selected per-isolate ceremony cap.
- [ ] Concurrent admission tests prove the local guard, durable budgets, typed
      retryable rejection, and global circuit breaker under load.
- [ ] Lifecycle persistence fits the reissued critical-path transaction and
      tail-latency budget.
- [ ] No JSON/base64 or whole-body copy appears in production profiles.
- [ ] Normal signing has zero added latency from this protocol.

After Phase 6A, targets may change only through a dated product/SLO decision
with measured evidence and independent reviewer approval.

### Security and Correctness Gates

- [ ] All reference and randomized differential vectors pass.
- [ ] P0 honest-execution and passive-corruption party-view tests pass; P1-P3
      pass every adversarial property named by their selected claim.
- [ ] Corrupt-A and corrupt-B harnesses run for every candidate. Behaviors
      outside P0/P1 are documented as exclusions rather than silently counted as
      passing security tests.
- [ ] P2/P3 ensure one malicious A or B obtains no joined secret and produces a
      valid output or transcript-verifiable abort.
- [ ] Selected provenance, selective-failure, and output-equivocation tests pass
      to the extent claimed by the frozen profile.
- [ ] Degenerate output-randomness and post-circuit scalar replacement tests are
      rejected to the extent claimed; P0/P1 residual active attacks are recorded
      explicitly.
- [ ] Noncanonical, identity, small-order, torsion, and non-prime-subgroup point
      vectors are rejected.
- [ ] Selected session/ticket crash, replay, rollback, restore, and retry tests
      pass.
- [ ] Epoch-floor rollback, circuit rollback, stale-ticket activation, and
      post-drain replay tests pass.
- [ ] Output commitments and `2 * X_client - X_server = A_pub` pass.
- [ ] FROST verifying shares satisfy `V_client + V_server = A_pub` and all
      golden signing vectors.
- [ ] Logs, errors, traces, and persistence contain no labels, OT state, masks,
      inputs, seed shares, or plaintext output shares.
- [ ] Constant-time review passes for native and compiled WASM.
- [ ] Dependency, supply-chain, fuzz, and malformed-input reviews pass.
- [ ] Independent cryptographic and deployment reviews approve the exact
      artifacts, selected claim, and explicit exclusions.

### Cost Gate

- [ ] Recheck pricing and contract terms for the selected production platform.
- [ ] Report account minimums, requests, CPU, storage, preprocessing, burn, and
      logging costs separately.
- [ ] Replace illustrative CPU scenarios with deployed per-candidate
      measurements.
- [ ] Exclude the HSS simulator from Yao release evidence.
- [ ] Record cost per one million successful ceremonies and per attempted
      ceremony.
- [ ] Report adversarial disconnect and burn cost at every wallet,
      organization, tenant, and global cap.

### Decision Rule

Release the strongest reviewed profile that passes the absolute and incremental
latency SLO plus every gate required by its exact claim. Evaluate P2 first, then
coherent P1 profiles, then P0. P3 releases only when its just-in-time latency
independently wins the same comparison. Total cost breaks ties between profiles
that meet the online SLO.

For each serious security profile, evaluate separate-account Workers, then
separate-account Containers, then independently administered native services
when a platform tripwire fires. Select exactly one security profile and one
platform. P0 is the production fallback when stronger profiles exceed latency,
effort, or operational budgets; its capability document must state the honest-
execution and passive-corruption assumptions prominently.

Stop when P0 misses the SLO, mandatory 80/20 controls, honest-execution
correctness, passive privacy, constant-time, independent-administration, or
review gates. No request may downgrade the frozen deployment profile.

Succinct HSS is outside the release decision and receives no further
implementation work.

## Cross-Phase Deployment Obligations

- [ ] Capture browser network waterfalls against the final asset host for
      Ed25519 registration, recovery, refresh, export and normal signing plus
      ECDSA registration, recovery, refresh, export and normal signing. Verify
      the locally frozen operation-lazy closures under deployed cache policy.

These obligations were previously mixed into local Phases 12, 14, and 14B.
They open only after Phase 13A records a deployment viability `go`.

- [ ] Deploy ECDSA Deriver A and Deriver B under independent account,
      credential, release, storage, backup, log, and approval authorities.
      Production manifests reject one-account bindings, shared deploy
      principals, production Service Bindings, and shared bearer credentials.
- [ ] Enforce signed HTTPS and the same independent-account deployment guards
      for every production ECDSA lifecycle.
- [ ] Delete every losing P0-P3 ceremony entrypoint, security-profile spike,
      inactive dependency path, backend identifier, base64 table field, and
      shared A/B credential after Phase 6A selects one profile.
- [ ] Update capability responses and selected-profile diagrams after Phase 6A.
- [ ] Require production configuration to contain only the Phase 6A-selected
      separate-account Streaming Yao security and platform profile for
      Ed25519.
- [ ] Prove the selected ECDSA lifecycle uses independently administered A/B
      authorities in deployed topology evidence.

## Phase 15: Independent Review and Production Burn-In

Status: **local Phase 14B prerequisite satisfied; deferred until the Phase 13A
viability decision, selected-profile production hardening, and deployed release
evidence are complete**

Goal: produce durable release evidence under the real operator model.

### TODO

- [ ] Obtain final independent cryptographic audit.
- [ ] Obtain an independent boundary and credential audit for the selected
      production platform.
- [ ] Have A and B operators independently reproduce artifact digests.
- [ ] Sign deployment manifests and account-separation attestations.
- [ ] Run staged traffic with the selected lifecycle and a conservative pool
      depth only when prepositioning is selected.
- [ ] Monitor p50/p95/p99, CPU, memory, burn rate, retries, storage, and cost.
- [ ] Exercise account credential revocation and peer-key rotation.
- [ ] Exercise one unavailable role and every corruption behavior covered by the
      selected profile; record P0/P1 active deviations as explicit exclusions.
- [ ] Record incident, rollback, and wallet-continuity procedures.
- [ ] Publish the exact production security claim and exclusions.

### Exit Gate

- [ ] Audit findings are closed or explicitly accepted at the required level.
- [ ] Burn-in meets security, latency, reliability, and cost gates.
- [ ] Independent operators attest to distinct control planes and artifact
      identity.

# Refactor 94B: Cold ECDSA Registration Latency

Date created: July 28, 2026

Status: planned

## Objective

Restore cold Email OTP and passkey registration to a 2–3 second
post-confirmation wall time by removing or hiding the cold latency in strict
ECDSA `respond` and `activate`.

This plan is a focused continuation of
`docs/refactor-94A-performance-regression.md`. Refactor 94A removed obsolete
registration persistence and orchestration. Refactor 94B owns the remaining
cold ECDSA path. The lazy Ed25519 work in `docs/refactor-94-lazy-yaos.md` remains
independent.

## Measured Regression

### Passkey production sample

The July 28 production passkey trace measured:

| Boundary | Duration |
| --- | ---: |
| Total registration | 25,309 ms |
| WebAuthn confirmation | 17,484 ms |
| Time after WebAuthn | approximately 5,990 ms |
| Registration start | 504 ms |
| ECDSA branch | 4,198 ms |
| ECDSA Gateway respond | 2,102 ms |
| Browser ECDSA creation, verification, and finalization | 34 ms |
| ECDSA Gateway activate | 2,061 ms |
| Registration finalize | 514 ms |
| Passkey session sealing and local persistence | 628 ms |

The WebAuthn interval includes the browser and operating-system authenticator
ceremony. It is reported separately and excluded from the post-confirmation
target. The approximately six-second interval after WebAuthn is the product
regression owned here.

### Cold/warm evidence across authentication methods

Email OTP and passkey use the same strict ECDSA registration path. Production
samples have measured:

| Shape | Respond + activate |
| --- | ---: |
| Cold passkey sample | 4,163 ms |
| Cold Email OTP samples | approximately 3,300–5,000 ms |
| Warm Email OTP sample | 611 ms |

Browser ECDSA work remains tens of milliseconds. The large cold/warm delta is
inside the deployed Gateway, Router, role Worker, and Durable Object graph.

### Correlated Yao evidence

The passkey sample also exposed the internal Router timing for the concurrently
executing Yao branch:

| Router boundary | Duration |
| --- | ---: |
| Pair preparation | 1,307 ms |
| Role execution | 674 ms |
| SigningWorker delivery | 934 ms |
| Gateway D1 claim + terminal commit | 42 ms |

ECDSA and Yao use the same Router, Deriver A, Deriver B, and SigningWorker
deployments. These timings strongly implicate cold role transitions. They do
not yet distinguish Worker startup, role-local Durable Object wakeup, host
preload, or protocol work.

## Current Cold Graph

### ECDSA respond

```text
browser
  -> Gateway
     -> D1 respond claim
     -> Router service binding
        -> Router lifecycle Durable Object claim
        -> Deriver A service binding ─┐
        │  -> root metadata DO        │ concurrent
        │  -> host preload            │
        │  -> proof generation        │
        -> Deriver B service binding ─┘
           -> root metadata DO
           -> host preload
           -> proof generation
        -> Router lifecycle completion
     -> D1 respond terminal CAS
  -> browser proof verification
```

### ECDSA activate

```text
browser
  -> Gateway
     -> D1 activation claim
     -> Router service binding
        -> SigningWorker service binding
           -> HPKE material reconstruction
           -> SigningWorker output Durable Object activation
     -> normal-signing session + budget Durable Object provisioning
     -> D1 activation terminal CAS
     -> runtime-policy read
     -> wallet-session JWT creation
```

The browser proof-verification boundary between these operations is required.
The two public requests cannot be collapsed into one request without removing
that verification boundary.

## Diagnosis

### Confirmed

1. The regression is shared by Email OTP and passkey registration.
2. Browser ECDSA computation is not the bottleneck.
3. Warm ECDSA completes substantially faster than cold ECDSA.
4. D1 is not the dominant Yao cost in the correlated passkey trace.
5. `respond` and `activate` each cross several Worker and Durable Object
   boundaries.
6. The role Worker WASM artifacts are large enough to make startup cost worth
   measuring: approximately 4.5 MB for Router, 6.6 MB for Deriver A, 6.5 MB
   for Deriver B, and 3.7 MB for SigningWorker in the current local release
   build.

### Still unmeasured

1. Gateway D1 claim and terminal-CAS duration for each ECDSA operation.
2. Router JWT verification and request parsing.
3. Router lifecycle claim and completion duration.
4. Deriver service-binding wait per role.
5. Root metadata Durable Object load per role.
6. Deriver host construction and proof computation per role.
7. SigningWorker startup, HPKE work, and output Durable Object activation.
8. Normal-signing session and budget provisioning.
9. Runtime-policy lookup and wallet-session JWT creation.
10. Deployed `startup_time_ms` for each role artifact.

Refactor 94B does not select a structural rewrite until these intervals are
visible in one cold trace and one immediate warm trace.

## Required Invariants

1. The browser verifies both exact Deriver proof bundles before activation.
2. Every remote irreversible effect is preceded by a durable typed claim.
3. Exact replay returns the stored pending activation or activation result.
4. Conflicting replay returns a typed conflict.
5. A response lost after a durable effect reconciles without repeating that
   effect.
6. Deriver A and Deriver B retain independent secret custody.
7. Root shares remain outside Gateway, Router, D1, and shared caches.
8. Warmup never creates ceremony state, reserves a wallet, consumes a grant,
   advances lifecycle state, or writes signing material.
9. Warmup failure never changes registration behavior or error handling.
10. Diagnostics never influence lifecycle control flow.
11. Timing headers contain fixed metric names and numeric durations only.
12. No account, wallet, email, credential, session, ciphertext, root-share, or
    other identifying value enters a timing header.
13. No transaction or `blockConcurrencyWhile()` region encloses a service
    binding, network request, timer, polling loop, or cryptographic ceremony.
14. No public unauthenticated role-warmup route is introduced.
15. No legacy route, runtime selector, compatibility flag, or duplicate
    registration implementation is added.

## Performance Targets

Targets exclude Google selection, WebAuthn, Touch ID, and other user-controlled
prompt time.

| Boundary | Warm target | Cold target |
| --- | ---: | ---: |
| ECDSA Gateway respond | ≤ 500 ms | ≤ 900 ms |
| ECDSA Gateway activate | ≤ 350 ms | ≤ 650 ms |
| Strict ECDSA branch | ≤ 1.0 s | ≤ 1.75 s |
| Registration start + finalize | ≤ 750 ms | ≤ 1.0 s |
| Wallet ready after confirmation | 2–3 s | ≤ 3.5 s |

The cold target is measured after a deployment or sufficient idle time to
evict the role isolates. A second immediate registration supplies the warm
comparison.

## Phase 0: Instrument Every Cold Boundary

- [x] Preserve the July 28 passkey baseline in this plan.
- [x] Separate the WebAuthn interval from post-authentication product latency.
- [ ] Propagate the existing opaque trace correlation value through ECDSA
      `respond` and `activate` without changing request or response bodies.
- [x] Add Gateway `Server-Timing` metrics for:
  - [x] D1 claim — `ecdsa_respond_d1_claim`, `ecdsa_activate_d1_claim`;
  - [x] Router service-binding call — `ecdsa_respond_router`,
        `ecdsa_activate_router`;
  - [x] D1 terminal CAS — `ecdsa_respond_d1_commit`,
        `ecdsa_activate_d1_commit`, both marked in `finally` so a reconciled
        CAS conflict is still measured;
  - [x] reconciliation when exercised — `ecdsa_respond_reconcile`,
        `ecdsa_activate_reconcile`;
  - [x] session and budget provisioning — `ecdsa_activate_session_provision`,
        plus `ecdsa_activate_bootstrap`;
  - [x] runtime-policy lookup — `ecdsa_activate_policy_lookup`;
  - [x] wallet-session JWT creation — `ecdsa_activate_jwt_mint`;
  - [x] total route duration — `ecdsa_respond_total`, `ecdsa_activate_total`.

Timings ride an internal result field that the route strips into the header,
so both wire bodies stay byte-identical. The two routes have a single
transport (`cloudflare/routes/walletRegistration.ts`), so there is no other
serializer that could leak the field.
- [ ] Add Router `Server-Timing` metrics for:
  - [ ] token verification and admission parsing;
  - [ ] lifecycle claim;
  - [ ] Deriver A and B wall time;
  - [ ] each Deriver service-binding response;
  - [ ] lifecycle completion;
  - [ ] SigningWorker service-binding call;
  - [ ] total Router operation duration.
- [ ] Add role-local metrics for:
  - [ ] runtime and binding parsing;
  - [ ] root metadata Durable Object load;
  - [ ] signer-host construction;
  - [ ] proof generation;
  - [ ] HPKE material reconstruction;
  - [ ] SigningWorker output Durable Object activation.
- [ ] Merge nested timing headers at each service-binding boundary.
- [ ] Expose `Server-Timing` on the two public Gateway responses.
- [ ] Parse the raw headers in the browser and fold the metrics into the
      existing registration timing summary.
- [ ] Log whether each expected raw header was present without logging its raw
      contents.
- [x] Add one behavioral test proving unknown or malformed metrics cannot
      affect registration — `tests/unit/ecdsaRegistrationServerTiming.unit.test.ts`.
      It caught a real defect: the Yao metric lookup used property access on an
      object literal, so a metric named `__proto__` or `constructor` resolved
      against `Object.prototype` and was recorded as a bucket. Now a `Map`.
- [ ] Record one cold and one warm Email OTP registration.
- [ ] Record one cold and one warm passkey registration.
- [ ] Capture deployed role `startup_time_ms` and upload size from the exact
      tested artifacts.

Acceptance:

- one trace accounts for at least 95% of each public ECDSA request;
- child spans never exceed their parent interval after accounting for
  concurrency;
- response bodies, execution order, retries, and lifecycle decisions remain
  unchanged;
- the trace distinguishes Worker/service startup from Durable Object and
  cryptographic work.

## Phase 1: Prewarm The Existing Topology

Use the already authorized registration-intent execution as the warmup trigger.
The Gateway schedules best-effort internal warmup after the intent is admitted,
leaving Google selection or WebAuthn time available to absorb startup.

- [ ] Define one private, authenticated Router warmup command.
- [ ] Have the Router warm Deriver A, Deriver B, and SigningWorker concurrently
      through existing service bindings.
- [ ] Make each role validate its runtime and load only stable startup data.
- [ ] Warm stable root-metadata and SigningWorker Durable Object instances with
      read-only operations where Phase 0 proves their wakeup is material.
- [ ] Schedule warmup with the request execution context so it survives the
      intent response without delaying that response.
- [ ] Bind warmup eligibility to a successfully admitted registration intent.
- [ ] Coalesce repeated warmups for the same request execution without global
      request state.
- [ ] Emit a typed best-effort warmup outcome for diagnostics only.
- [ ] Prove warmup performs no lifecycle or signing-material writes.
- [ ] Delete any existing browser-only “signer worker prewarm” naming that
      could be mistaken for server topology warmup, or rename it precisely.

Acceptance:

- a cold registration after an admitted intent reaches the warm ECDSA target;
- a warmup failure produces the same registration behavior as no warmup;
- the warmup route is unavailable from the public Internet;
- all internal calls use service bindings.

## Phase 2: Reduce Worker Startup Cost If It Dominates

Enter this phase only if Phase 0 attributes at least 300 ms of the cold ECDSA
branch to role Worker startup after Phase 1.

- [ ] Compare each deployed `startup_time_ms` with its raw and compressed
      artifact size.
- [ ] Produce a role-by-role dependency and symbol inventory for Router,
      Deriver A, Deriver B, and SigningWorker.
- [ ] Make protocol and role dependencies optional where the active entrypoint
      does not use them.
- [ ] Remove entrypoint-unreachable protocol adapters and generated bindings
      from each role artifact.
- [ ] Preserve one deployment per custody role; do not duplicate role secrets
      across ECDSA-only and Yao-only Workers unless a measured follow-up plan
      explicitly approves that custody expansion.
- [ ] Compare `opt-level=3` with a size-oriented profile using the real cold
      registration benchmark and the cryptographic kernel benchmark.
- [ ] Select the profile with the lowest end-to-end cold registration time.
      Artifact size alone does not decide the profile.
- [ ] Require at least a 30% startup-time reduction or delete the experimental
      build changes.

Acceptance:

- selected artifacts preserve all Rust vectors and role-separation tests;
- cold end-to-end registration improves without materially regressing warm
  proof generation or Yao execution;
- no duplicate Worker topology or secret distribution remains.

## Phase 3: Reduce ECDSA Respond Latency If It Remains Above Target

Enter this phase only when the Phase 0 trace identifies a remaining respond
interval above 900 ms.

- [ ] Keep the existing atomic Gateway D1 claim and terminal CAS.
- [ ] Keep the Router lifecycle claim before Deriver execution and exact
      completion after it.
- [ ] Keep Deriver A and B concurrent.
- [ ] If root metadata loading dominates, replace repeated reconstruction with
      an epoch-bound role-local read path that preserves role authority and
      invalidates exactly on epoch change.
- [ ] If host construction dominates, cache only validated immutable public
      configuration; never cache request state, plaintext, root-share bytes, or
      I/O objects across requests.
- [ ] If lifecycle storage dominates, reduce serialization and stored payload
      size while preserving claim-before-effect and exact replay.
- [ ] If service-binding wait dominates after startup is removed, measure
      scheduling contention between concurrent ECDSA and Yao work before
      changing topology.
- [ ] Delete the superseded read, conversion, and serialization paths in the
      same change.

Acceptance:

- cold respond is at or below 900 ms;
- the browser still verifies exact A/B proof bundles;
- exact replay and conflicting replay retain their typed outcomes;
- no external I/O occurs inside a Durable Object transaction.

## Phase 4: Reduce ECDSA Activate Latency If It Remains Above Target

Enter this phase only when the Phase 0 trace identifies a remaining activate
interval above 650 ms.

- [ ] Move normal-signing session and budget provisioning into the Router
      activation execution path so the Gateway makes one Router call and one
      terminal D1 CAS.
- [ ] Return one typed combined result that requires both SigningWorker
      activation and session/budget provisioning.
- [ ] Preserve durable claim-before-effect and reconcile either durable result
      after a lost response.
- [ ] Keep the browser-verified client facts and exact pending activation as
      required activation inputs.
- [ ] Remove the Gateway-side post-Router provisioning call after the combined
      path is live.
- [ ] Fold runtime-policy scope needed for the wallet-session JWT into the
      claimed activation state so the public handler does not perform another
      ceremony lookup.
- [ ] Create the wallet-session JWT after the combined durable result and
      before the public response.
- [ ] If SigningWorker output activation itself dominates, reduce its Durable
      Object payload and storage work before considering a new coordinator.
- [ ] Do not claim atomicity across separate Durable Objects. Model partial
      durable success explicitly and reconcile it.

Acceptance:

- cold activate is at or below 650 ms;
- Gateway performs no normal-signing provisioning call after Router activation;
- registration returns success only after SigningWorker material and
  normal-signing authority are durable;
- a lost response resumes without repeating either durable effect.

## Phase 5: Remove The Remaining Passkey-Only Tail

The measured passkey sample spends another 628 ms sealing and persisting its
warm ECDSA session after the network ceremony.

- [ ] Keep this work separate from ECDSA server timing.
- [ ] Reuse the Shamir 3-pass prewarm work already planned for passkey
      registration.
- [ ] Measure server seal, runtime setup, server route, client unseal, and local
      persistence independently after prewarm.
- [ ] Start safe local preparation during the WebAuthn ceremony where it does
      not retain or derive credential material early.
- [ ] Parallelize local session persistence with registration finalization only
      if failure cleanup is deterministic and covered by a behavioral test.
- [ ] Delete abandoned prewarm attempts and duplicate local-session paths.

Acceptance:

- passkey-only post-network work is at or below 250 ms;
- no passkey secret or PRF output has a longer lifetime;
- failed registration leaves no usable orphaned local session.

## Phase 6: Validation And Deployment

- [ ] Run focused ECDSA registration lifecycle, replay, conflict, and
      reconciliation tests.
- [ ] Run focused Router, Deriver, SigningWorker, and Durable Object tests.
- [ ] Run the relevant Rust vectors and TypeScript type fixtures.
- [ ] Run one optimized local Email OTP registration and one optimized local
      passkey registration.
- [ ] Deploy backend and frontend instrumentation to staging.
- [ ] Capture one cold and one warm registration for each authentication
      method in staging.
- [ ] Implement only the Phase 2, 3, or 4 optimization selected by those
      timings.
- [ ] Repeat staging validation and confirm all cold targets.
- [ ] Deploy backend roles before the frontend timing consumer when the metric
      contract changes.
- [ ] Deploy production and capture one cold and one warm manual registration
      for each authentication method.
- [ ] Remove temporary verbose console diagnostics after the timing summary
      carries every required bucket.
- [ ] Update `docs/refactor-94A-performance-regression.md` with the final cause,
      implementation, and measured gain.
- [ ] Run `pnpm check` and classify any failure according to `AGENTS.md` before
      changing code or fixtures.
- [ ] Run `git diff --check`.

Acceptance:

- Email OTP and passkey share the same measured ECDSA path;
- typical wallet-ready time is 2–3 seconds after confirmation;
- cold wallet-ready time is at or below 3.5 seconds;
- no correctness, replay, custody, or crash-convergence invariant regresses;
- no legacy registration route, feature flag, selector, duplicate Worker, or
  compatibility implementation remains.

## Phase Dependencies

```text
Phase 0: exact ECDSA timing
  |
  +--> Phase 1: topology prewarm
  |      |
  |      +--> remeasure
  |
  +--> Phase 2: bundle/startup reduction       [only if startup dominates]
  +--> Phase 3: respond-path reduction         [only if respond remains high]
  +--> Phase 4: activation-path reduction      [only if activate remains high]

Phase 5: passkey local tail                     [independent after Phase 0]

Selected optimization phases
  +--> Phase 6: staging and production validation
```

Phase 0 is the gate. Phase 1 is the smallest likely cold-path win and uses the
existing user-interaction window. Phases 2–4 are conditional. Their measured
intervals determine which one is implemented, preventing another broad
performance refactor based on speculation.

## Completion Criteria

Refactor 94B is complete when:

1. ECDSA timing accounts for at least 95% of cold `respond` and `activate`;
2. cold ECDSA registration completes at or below 1.75 seconds;
3. warm ECDSA registration completes at or below 1.0 second;
4. typical Email OTP and passkey registration reaches wallet-ready state in
   2–3 seconds after confirmation;
5. first-use cold registration reaches wallet-ready state within 3.5 seconds;
6. exact replay, conflict rejection, uncertainty reconciliation, and
   claim-before-effect remain verified;
7. role-secret custody remains unchanged;
8. no diagnostics value influences execution;
9. every replacement deletes its obsolete path; and
10. the final document records the measured cold cause and realized gain.

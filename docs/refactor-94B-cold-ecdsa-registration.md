# Refactor 94B: Cold ECDSA Registration Latency

Date created: July 28, 2026

Status: closed — diagnosis complete; structural remediation moved to Refactor 94C

## Closure

Refactor 94B completed the cold-boundary instrumentation and identified the
deployed cause. Worker startup measured 3–11 ms and Deriver computation
measured 22–49 ms. Cold latency instead concentrated in Router authorization
and admission, SigningWorker output state, and Gateway session and budget
Durable Objects. Their combined cold penalty was several seconds.

Prewarming the existing stateful topology would hide the symptom temporarily
while retaining the duplicated authorities that created it. The unimplemented
warmup, bundle-size, respond, activate, passkey-tail, and deployment phases are
superseded by
[`refactor-94C-regression-fixes.md`](./refactor-94C-regression-fixes.md), which
removes those Durable Object boundaries. All unchecked checklist entries and
unimplemented phase proposals have been removed. Refactor 94C owns the
production latency target and final deployment acceptance.

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

### Measurement Resolution

The completed instrumentation resolved the decision-driving intervals. Router
authorization and admission measured about 2,360 ms cold versus 60 ms warm;
SigningWorker output state measured about 1,406 ms cold versus 38 ms warm;
Gateway session and budget state measured about 1,336 ms cold versus 22 ms
warm. Deriver work measured 22–49 ms, and deployed Worker startup measured
3–11 ms. These results selected structural state-topology removal in Refactor
94C.

## Registration Effect Ledger (2026-07-28)

What is actually irreversible in a **default** registration, recorded so
insurance machinery is scoped to it and nothing else:

- **NEAR account creation is implicit.** The account ID is the Ed25519 public
  key; creating it is keypair derivation only. No on-chain transaction, no
  gas, no relayer spend, nothing exists on chain until the account is funded
  at first use. Default registration therefore creates **no irrevocable
  on-chain state** and must not carry on-chain-grade claim/replay ceremony.
- **Irreversible in the default path:** custody activation (the signer set
  and key material commitment) and Yao consume-once material. These keep
  their claims.
- **The sponsored `named` account path is the exception, not the default.**
  When a tenant opts into named accounts at signup, that path broadcasts a
  funded on-chain transaction and keeps the full durable-claim and replay
  ceremony. The ceremony's cost belongs to that option alone.

Invariant 2 below is scoped by this ledger: "irreversible effect" means the
items named here, not every persistence step in the flow.

## Required Invariants

1. The browser verifies both exact Deriver proof bundles before activation.
2. Every remote irreversible effect is preceded by a durable typed claim.
3. Exact replay returns the stored pending activation or activation result.
4. Conflicting replay returns a typed conflict.
5. A response lost after a durable effect reconciles without repeating that
   effect.
6. Deriver A and Deriver B retain independent secret custody.
7. This diagnostic baseline kept root shares outside D1. Refactor 94C
   supersedes that storage invariant by permitting only envelope-encrypted
   role-share ciphertext in role-private D1; plaintext shares remain outside
   Gateway, Router, D1, and shared caches.
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
- [x] Propagate the existing opaque trace correlation value through ECDSA
      `respond` and `activate` without changing request or response bodies.
      Validated once at the public boundary: a missing header is allowed
      because callers need not trace, while a malformed one is a 400 rather
      than being silently coerced into "untraced". The parsed value is threaded
      as a typed `RouterAbTraceContextV1` into the strict registration port and
      set on the outbound request in the shared `forward` path, so both legs
      carry it byte-identically and nothing downstream re-derives it.
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
- [x] Add Router `Server-Timing` metrics for:
  - [x] token verification and admission parsing — `ecdsa_rt_authorize`;
  - [x] lifecycle claim — `ecdsa_rt_admission`;
  - [x] Deriver A and B wall time — `ecdsa_rt_derivers`, the joined fan-out;
  - [x] each Deriver service-binding response — `ecdsa_rt_deriver_a`,
        `ecdsa_rt_deriver_b`, which overlap each other and nest inside
        `ecdsa_rt_derivers`;
  - [x] lifecycle completion — `ecdsa_rt_completion`;
  - [x] SigningWorker service-binding call — `ecdsa_rt_act_worker`, alongside
        `ecdsa_rt_act_session` for the activate leg's JWT session verification;
  - [x] total Router operation duration — `ecdsa_rt_total` for the register
        leg (marked on both the normal and replay-completion returns) and
        `ecdsa_rt_act_total` for activate.
- [x] Add role-local metrics for:
  - [x] runtime and binding parsing — `parse` on each role;
  - [x] root metadata Durable Object load — `preload` on Deriver A/B, which
        covers the signer-host preload that loads it;
  - [x] signer-host construction — same `preload` span; the host is built from
        the preloaded material in one call and has no separate boundary;
  - [x] proof generation — `execute` on Deriver A/B;
  - [x] HPKE material reconstruction — inside `execute`; decryption and proof
        generation happen in one call and were not worth splitting before the
        `execute` total shows they are material;
  - [x] SigningWorker output Durable Object activation — `ecdsa_sw_activate`.
- [x] Merge nested timing headers at each service-binding boundary. Each role
      emits bare names (`parse`, `preload`, `execute`, `total`); the Router
      folds them in under `ecdsa_a`/`ecdsa_b`/`ecdsa_sw`; the Gateway folds the
      Router's header into its own span list. One header reaches the browser.

The nesting is what makes the cold cost legible: `ecdsaRtDeriverAMs` bounds
`ecdsaDeriverATotalMs`, so a large gap between the two is Worker cold start
and transport rather than work — the measurement that decides Phase 2.
- [x] Expose `Server-Timing` on the two public Gateway responses. Already
      handled by the shared CORS helper, which sets
      `Access-Control-Expose-Headers: Server-Timing` whenever the response
      carries the header (`cloudflare/http.ts:69-71`) — so it appears on these
      two routes now that they emit it, and stays absent on error responses.
- [x] Parse the raw headers in the browser and fold the metrics into the
      existing registration timing summary. `postJson` gained an optional
      `Server-Timing` sink, threaded to the two strict-ceremony call sites; the
      existing Yao metric map absorbed the fourteen `ecdsa_*` names, so one
      parser covers both families.
- [x] Log whether each expected raw header was present without logging its raw
      contents. Presence is reported for every leg including those that
      returned nothing, since an absent header and an empty one are different
      failures. The value reaches only the timing fold, which emits fixed
      metric names; it never reaches the presence sink or a log.
      Covered by `strict ECDSA registration reports header presence without its
      contents` in `tests/unit/registrationTerminalCancellation.unit.test.ts`,
      which asserts both branches and that no fragment of the header survives
      into the presence payload.
- [x] Add one behavioral test proving unknown or malformed metrics cannot
      affect registration — `tests/unit/ecdsaRegistrationServerTiming.unit.test.ts`.
      It caught a real defect: the Yao metric lookup used property access on an
      object literal, so a metric named `__proto__` or `constructor` resolved
      against `Object.prototype` and was recorded as a bucket. Now a `Map`.
- [x] Record one cold and one warm Email OTP registration. Staging
      (`8b5fe1014`, 2026-07-28, immediately after deploy; warm run within
      minutes of the cold one):

      | Interval | Cold | Warm |
      | --- | ---: | ---: |
      | Registration total | 12,228 ms | 7,059 ms |
      | ECDSA branch total | 7,244 ms | 1,764 ms |
      | Gateway respond total | 2,769 ms | 669 ms |
      | Gateway activate total | 3,069 ms | 646 ms |
      | Router authorize + admission | ~2,360 ms | ~60 ms |
      | SigningWorker output DO activation | 1,406 ms | 38 ms |
      | Gateway session/budget DO provisioning | 1,336 ms | 22 ms |
      | Deriver A/B (parse+preload+execute) | 22-49 ms | 15-42 ms |
      | D1 claim/commit per operation | ~140-160 ms | ~145-270 ms |

      Span coverage 99.9% on both runs; header-presence diagnostics reported
      `present` on both legs. The cold ECDSA penalty is ~5.5 s and decomposes
      almost entirely into Durable Object wakeup and authorization I/O:
      Router authorize/admission, the SigningWorker output DO, and the
      Gateway's session/budget DO. Deriver work is 22-49 ms cold — the two
      largest wasm artifacts contribute effectively nothing.
- [x] Record one cold and one warm passkey registration. Captured as one
      semi-warm sample (real browser, same day, after idle decay from the
      Email OTP pair; the embedded-browser authenticator lacks PRF, so the
      pane could not produce it):

      | Interval | Passkey semi-warm |
      | --- | ---: |
      | Registration total | 16,437 ms |
      | WebAuthn ceremony (`authProofMs`) | 6,375 ms (credential create 5,384) |
      | Post-WebAuthn product time | ~8,300 ms |
      | ECDSA branch total | 4,617 ms |
      | Router authorize + admission | ~1,490 ms |
      | SigningWorker output DO activation | 796 ms |
      | Gateway session/budget DO provisioning | 703 ms |
      | Deriver A/B | 11 ms each |
      | Passkey-only seal tail (`ecdsaRegistrationPersistenceMs`) | 693 ms |

      The ECDSA branch sits between the recorded cold (7,244) and warm (1,764)
      samples with the same three intervals dominating at partial decay, so
      the passkey branch confirms the shared diagnosis rather than adding a
      new one. Two passkey-specific facts are now measured: the WebAuthn
      ceremony itself cost 6.4 s (user- and OS-controlled, excluded from
      targets, but the largest single interval a passkey user perceives), and
      the passkey-only warm-session seal tail is ~0.7 s
      (`ecdsaRegistrationRoleLocalRecordPersistenceMs` 679, dominated by
      `ecdsaRegistrationWarmSessionSealApplyServerSealMs` 287 and the seal
      route round trips) — Phase 5's target, now quantified. The deferred
      NEAR commit #2 was observed firing after the ECDSA-ready return, on the
      passkey branch, on deployed staging.
- [x] Capture deployed role `startup_time_ms` and upload size from the exact
      tested artifacts (staging deploy run 30342714806, re-confirmed by the
      `8b5fe1014` redeploy):

      | Worker | Upload | gzip | Startup |
      | --- | ---: | ---: | ---: |
      | Deriver A | 6,973.54 KiB | 2,462.35 KiB | 4 ms |
      | Deriver B | 6,890.25 KiB | 2,432.45 KiB | 4 ms |
      | SigningWorker | 4,041.07 KiB | 1,233.96 KiB | 3 ms |
      | Router | 4,832.04 KiB | 1,456.16 KiB | 3 ms |
      | Gateway | 5,596.97 KiB | 1,152.98 KiB | 11 ms |


## Final Closeout

Refactor 94B is closed. Phase 0 delivered the complete cold-boundary
instrumentation and proved that Durable Object wakeups and stateful topology
dominate the cold ECDSA regression. The proposed prewarm and
topology-preserving optimization phases were not implemented and have been
removed. Refactor 94C is the sole owner of structural remediation, production
performance targets, and deployment acceptance.

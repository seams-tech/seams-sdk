# Refactor 95: Keep Router A/B Workers Warm

## Status

Planned.

## Goal

Increase the probability that registration, unlock, and signing reach warm
Gateway, Router, Deriver A, Deriver B, and SigningWorker isolates when product
traffic is sparse.

Run one lightweight prewarm chain every two minutes. The chain exercises the
real Worker and crypto-runtime initialization paths while performing no D1
writes, Durable Object calls, ceremony creation, external RPCs, or custody
effects.

This is a low-cost launch optimization. It complements the 94C cold-path work;
the measured cold path must remain functional and below its product ceiling.

## Expected Effect

At a two-minute interval, one environment produces approximately 21,600
heartbeat chains per month. Service-binding fan-out makes the request cost
small relative to ordinary product traffic.

The heartbeat should materially improve warm-hit probability for traffic near
the scheduled execution location. Cloudflare still controls isolate placement
and eviction, so the mechanism reduces cold starts rather than defining an
availability guarantee.

## Topology

```text
Cloudflare Cron (every 2 minutes)
  -> Gateway scheduled handler
     -> MPC_ROUTER /internal/prewarm
        -> DERIVER_A /internal/prewarm
        -> DERIVER_B /internal/prewarm
        -> SIGNING_WORKER /internal/prewarm
```

The Router calls all three role Workers concurrently. The Gateway does not add
direct Deriver bindings.

## Internal Contract

Use one internal path on every Router A/B Worker:

```text
POST /internal/prewarm
```

Requests use the existing Router A/B internal service-auth secret. Reject
requests without valid internal authentication. Do not expose a browser or
publishable-key route.

Each role returns a small typed response:

```ts
type WorkerPrewarmResultV1 = {
  kind: 'worker_prewarm_result_v1';
  role: 'router' | 'deriver_a' | 'deriver_b' | 'signing_worker';
  ok: true;
};
```

The Router returns success only after its three concurrent child calls return
success. No response contains configuration, key identifiers, policy, timing
internals, or secret-derived data.

## What Each Worker Warms

### Gateway

- Enter the deployed Gateway module through its scheduled handler.
- Parse the Router A/B topology and construct the existing MPC Router binding
  request.
- Make no tenant lookup and no database call.

### Router

- Parse and validate the deployed Router configuration, keyset, and local JWT
  verification material using existing constructors.
- Initialize the local routing/runtime code used by registration and signing.
- Call Deriver A, Deriver B, and SigningWorker prewarm endpoints concurrently.
- Make no D1 or Durable Object call.

### Deriver A and Deriver B

- Initialize the same Rust crypto modules and reusable runtime tables used by
  ECDSA derivation and Ed25519 Yao role execution.
- Parse role-local configuration and public-key material through production
  boundary parsers.
- Do not load root shares, create role sessions, decrypt custody state, or
  access role-private D1.

### SigningWorker

- Initialize the same Rust crypto/runtime modules used for activation,
  delivery, and signing.
- Parse role-local configuration through production boundary parsers.
- Do not access private D1, request a wallet budget, create a presign session,
  or wake the presign Durable Object.

## Implementation

### Phase 1: Role-local prewarm functions

- [ ] Add one pure, effect-free prewarm function to the Router, Deriver, and
      SigningWorker runtime surfaces.
- [ ] Reuse existing runtime/config constructors; do not create a second crypto
      initialization path.
- [ ] Ensure every function is safe to call repeatedly in the same isolate.
- [ ] Add the authenticated `/internal/prewarm` route to each role Worker.

### Phase 2: Router fan-out

- [ ] Implement Router prewarm as local initialization followed by concurrent
      service-binding calls to Deriver A, Deriver B, and SigningWorker.
- [ ] Apply a short timeout so one unhealthy role does not leave the scheduled
      event running indefinitely.
- [ ] Return one typed failure naming only the failed role; expose no internal
      error body or configuration.

### Phase 3: Gateway schedule

- [ ] Extend `d1RouterApiStagingWorker.ts`'s existing `scheduled` handler to
      call the MPC Router prewarm endpoint.
- [ ] Use `ctx.waitUntil` so the cron handler owns the full request without
      blocking unrelated Gateway work.
- [ ] Add `*/2 * * * *` to the rendered staging and production Gateway cron
      configuration.
- [ ] Keep local development unscheduled; expose a local command that invokes
      the same Gateway-to-Router chain once when manual verification is useful.

### Phase 4: Deploy and verify

- [ ] Deploy one coherent backend revision to staging.
- [ ] Confirm a cron invocation reaches Gateway, Router, both Derivers, and
      SigningWorker with HTTP 200 responses.
- [ ] Confirm the invocation performs zero D1 operations, zero Durable Object
      calls, and zero external network requests.
- [ ] Leave staging idle for at least ten minutes, then manually compare a
      registration with the 94C cold baseline: Email OTP 2,565 ms and passkey
      approximately 2–3 seconds.
- [ ] Deploy the same revision and cron schedule to production.

## Minimal Validation

- One Router test proving all three role bindings are called concurrently and
  repeated prewarm calls succeed.
- One route test proving missing internal authentication is rejected.
- One staging invocation proving the complete chain executes without storage
  or external effects.

Avoid a new framework, persistence record, feature flag, public health API, or
synthetic ceremony.

## Acceptance

Refactor 95 is complete when:

1. staging and production Gateways invoke the prewarm chain every two minutes;
2. all five deployed Worker roles execute their real initialization paths;
3. the heartbeat performs no D1 writes, Durable Object calls, external RPCs,
   or custody effects;
4. heartbeat failures do not affect product requests;
5. sparse-traffic registration shows fewer cold-path observations without
   weakening the 94C cold-path ceiling.


# Refactor 95: Keep Router A/B Workers Warm

## Status

Implemented and merged into `dev`. Staging and production deployment
verification remain.

## Goal

Increase the probability that registration, unlock, and signing reach warm
Gateway, Router, Deriver A, Deriver B, and SigningWorker isolates when product
traffic is sparse.

Run one lightweight prewarm chain every minute. Invoking each Worker loads
its deployed module and any existing lazy runtime initializer. The chain
performs no D1 writes, Durable Object calls, ceremony creation, external RPCs,
or custody effects.

This is a low-cost launch optimization. It complements the 94C cold-path work;
the measured cold path must remain functional and below its product ceiling.

## Expected Effect

At a one-minute interval, one environment produces approximately 43,200
heartbeat chains per month. Service-binding fan-out makes the request cost
small relative to ordinary product traffic.

The heartbeat should materially improve warm-hit probability for traffic near
the scheduled execution location. Cloudflare still controls isolate placement
and eviction, so the mechanism reduces cold starts rather than defining an
availability guarantee.

## Topology

```text
Cloudflare Cron (every minute)
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

Each role returns:

```json
{ "ok": true }
```

The Router returns success only after its three concurrent child calls return
success.

## What Each Worker Warms

### Gateway

- Enter the deployed Gateway module through its scheduled handler.
- Call the existing MPC Router service binding.

### Router

- Load the deployed Router module and existing lazy initialization, if any.
- Call Deriver A, Deriver B, and SigningWorker prewarm endpoints concurrently.

### Deriver A and Deriver B

- Load the deployed Rust/WASM module and existing lazy initialization, if any.

### SigningWorker

- Load the deployed Rust/WASM module and existing lazy initialization, if any.

## Implementation

### Phase 1: Internal endpoints

- [x] Add authenticated `/internal/prewarm` routes to Router, Deriver A,
      Deriver B, and SigningWorker.
- [x] Return `{ "ok": true }` after module initialization.
- [x] Call an existing lazy runtime initializer only where one already exists.

### Phase 2: Router fan-out

- [x] Implement Router prewarm as local initialization followed by concurrent
      service-binding calls to Deriver A, Deriver B, and SigningWorker.
- [x] Return `{ "ok": true }` when all three calls succeed; otherwise return a
      normal internal error.

### Phase 3: Gateway schedule

- [x] Extend `d1RouterApiStagingWorker.ts`'s existing `scheduled` handler to
      await the MPC Router prewarm endpoint.
- [x] Add `ROUTER_AB_PREWARM_ENABLED` to Gateway configuration. Skip the call
      when it is `false`.
- [x] Add `* * * * *` to the rendered staging and production Gateway cron
      configuration.

### Phase 4: Deploy and verify

- [ ] Deploy one coherent backend revision to staging.
- [ ] Confirm a cron invocation reaches Gateway, Router, both Derivers, and
      SigningWorker with HTTP 200 responses.
- [ ] Leave staging idle for at least ten minutes, then manually compare a
      registration with the 94C cold baseline: Email OTP 2,565 ms and passkey
      approximately 2–3 seconds.
- [ ] Deploy the same revision and cron schedule to production.

## Minimal Validation

- One Router test proving all three role bindings are called concurrently.
- One staging invocation proving the complete chain returns successfully.

Avoid a new framework, persistence record, public health API, synthetic
ceremony, or separate runtime abstraction.

## Acceptance

Refactor 95 is complete when:

1. staging and production Gateways invoke the prewarm chain every minute;
2. all five deployed Workers load their normal modules and existing lazy
   initializers;
3. the heartbeat performs no D1 writes, Durable Object calls, external RPCs,
   or custody effects;
4. heartbeat failures do not affect product requests;
5. sparse-traffic registration shows fewer cold-path observations without
   weakening the 94C cold-path ceiling.

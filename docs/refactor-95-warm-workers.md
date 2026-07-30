# Refactor 95: Keep Router A/B Workers Warm

## Status

Implemented locally. Staging and production deployment verification remain.

## Goal

Increase the probability that registration, unlock, and signing reach warm
Gateway, Router, Deriver A, Deriver B, and SigningWorker isolates when product
traffic is sparse.

Run one lightweight prewarm chain every minute. Invoking each Worker loads its
deployed module and any existing lazy runtime initializer. The chain performs
no D1 writes, Durable Object calls, ceremony creation, external RPCs, or
custody effects.

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

## Cost Estimate

Assumptions: a 30-day month, one Gateway Cron Trigger invocation per chain, and
Cloudflare Workers Standard pricing. Service-binding calls do not add request
fees; Cloudflare bills the initial Gateway invocation and aggregates CPU time
across the Gateway, Router, Deriver A, Deriver B, and SigningWorker. The Workers
Paid plan includes 10 million requests and 30 million CPU milliseconds per
month, then charges $0.30 per million requests and $0.02 per million CPU
milliseconds.

| Interval        | Chains per environment/month | Staging + production/month | Request overage if the included request allotment is already exhausted |
| --------------- | ---------------------------: | -------------------------: | ---------------------------------------------------------------------: |
| Every 1 minute  |                       43,200 |                     86,400 |                            $0.01296 per environment; $0.02592 for both |
| Every 2 minutes |                       21,600 |                     43,200 |                            $0.00648 per environment; $0.01296 for both |
| Every 3 minutes |                       14,400 |                     28,800 |                            $0.00432 per environment; $0.00864 for both |

The expected incremental charge is $0 while the account has enough included
request and CPU allocation remaining. CPU cost depends on measured runtime. At
10 ms of aggregate CPU per chain, one environment would use 432,000 CPU ms at
the one-minute interval, 216,000 CPU ms at the two-minute interval, or 144,000
CPU ms at the three-minute interval. If the included CPU allocation is
exhausted, the incremental CPU charge is aggregate chain CPU milliseconds
multiplied by $0.02 per million.

Pricing references: [Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
and [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/).

The five-Worker chain at a one-minute interval produces approximately 216,000
invocation logs per environment each month, or 432,000 across staging and
production. This remains within the Workers Paid plan's 20 million included log
events per month when the existing 100% invocation-log sampling is retained.

## Observability

Use Cloudflare's existing invocation logs for the Gateway scheduled event and
the four authenticated `/internal/prewarm` fetch invocations. Invocation logs
already report CPU time, wall time, Worker script identity, and
`$metadata.coldStart`, so no custom timing response or duplicate log event is
needed.

Filter the role invocations by `/internal/prewarm`, group by Worker script and
`$metadata.coldStart`, and compare cold and warm wall-time distributions. Report
the cold-start percentage as cold heartbeat invocations divided by all
successful heartbeat invocations for each Worker. The Gateway is grouped by its
one-minute Cron Trigger.

Observability references: [Workers invocation timing](https://developers.cloudflare.com/changelog/post/2025-04-09-workers-timing/)
and the [Workers Observability API](https://developers.cloudflare.com/api/resources/workers/subresources/observability/).

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

- Parse and validate the deployed Router runtime configuration through its
  existing constructor.
- Call Deriver A, Deriver B, and SigningWorker prewarm endpoints concurrently.

### Deriver A and Deriver B

- Load the deployed Rust/WASM module and parse and validate role-local runtime
  bindings through the existing constructor.

### SigningWorker

- Load the deployed Rust/WASM module and parse and validate its runtime bindings
  through the existing constructor.

## Implementation

### Phase 1: Internal endpoints

- [x] Add authenticated `/internal/prewarm` routes to Router, Deriver A,
      Deriver B, and SigningWorker.
- [x] Return `{ "ok": true }` after module and runtime-binding initialization.
- [x] Reuse each role's existing runtime constructor without accessing storage
      or custody state.

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
- [ ] Confirm invocation logs expose cold-start, CPU-time, and wall-time fields
      for all five Workers, then save the per-Worker cold/warm percentage query.
- [ ] Leave staging idle for at least ten minutes, then manually compare a
      registration with the 94C cold baseline: Email OTP 2,565 ms and passkey
      approximately 2–3 seconds.
- [ ] Deploy the same revision and cron schedule to production.

### Phase 5: Evaluate region-aligned external scheduling

Defer this phase until the Cloudflare Cron deployment has produced enough colo,
cold-start, and real-user telemetry for a useful comparison. Cloudflare runs
Cron Triggers on underutilized machines, so the scheduled chain may not warm the
execution locations that receive the next user requests.

- [ ] Measure heartbeat colo distribution and its overlap with real-user colo
      distribution.
- [ ] Establish per-Worker and full-chain cold-start rates for synthetic and
      real-user traffic under the Cloudflare Cron schedule.
- [ ] If placement overlap is poor, add a dedicated authenticated Gateway
      `POST /internal/prewarm` entrypoint for an external regional scheduler.
- [ ] Give the external scheduler a dedicated timestamped credential and replay
      window. Do not expose or reuse the Router A/B internal service-auth
      secret.
- [ ] Run one-minute probes only from regions justified by production traffic,
      starting with one region and adding others when measured traffic warrants
      them.
- [ ] Compare the external probe's colo overlap, full-chain warm rate, latency,
      reliability, and scheduler cost against the Cloudflare Cron baseline.
- [ ] Keep one scheduling mechanism after the comparison. Remove the weaker
      trigger and its configuration rather than maintaining duplicate paths.

The external request should enter the nearest Cloudflare location to its
scheduler. The Gateway then uses the existing service-binding chain, which runs
bound Workers on the same Cloudflare server by default. This improves regional
placement control without making Router, Deriver, or SigningWorker endpoints
public.

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
   weakening the 94C cold-path ceiling;
6. Worker invocation logs report per-role cold/warm percentages and latency
   distributions for the heartbeat path.

The follow-up operator dashboard, alerting, configuration, authorization, and
deployment separation are specified in
[`refactor-99B-MPC-control-plane.md`](./refactor-99B-MPC-control-plane.md).

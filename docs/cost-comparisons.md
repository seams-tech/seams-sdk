# Wallet Cost Comparisons

Date updated: June 25, 2026

Status: internal pricing and positioning notes. Public copy should use broader
claims until Seams has measured production signing costs.

## Summary

Seams provides self-hostable threshold embedded wallets that deploy to
Cloudflare. The cost advantage comes from paying for actual usage on Workers
and Durable Objects instead of operating always-on wallet infrastructure.

The defensible pricing claim:

> Seams can deliver self-hostable threshold embedded wallets with
> order-of-magnitude lower wallet infrastructure cost.

The internal planning estimate:

| Model | Estimated wallet infrastructure cost |
| --- | ---: |
| Seams optimized Cloudflare deployment | $10-$50 per 1M wallet operations |
| Seams conservative early deployment | $50-$200 per 1M wallet operations |
| Privy enterprise signature floor | $1,000 per 1M signatures |
| OpenFort public overage range | $4,000-$10,000 per 1M operations |
| Dynamic public pricing | Workload-dependent; page includes MAU and operation-based sections |

## Public Pricing Anchors

Cloudflare Workers Standard includes 10M requests and 30M CPU ms each month on
the paid plan, then charges $0.30 per additional 1M requests and $0.02 per
additional 1M CPU ms. Durable Objects add 1M included requests, then $0.15 per
1M requests, plus duration pricing at $12.50 per 1M GB-s.

Sources:

- [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cloudflare Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)

Privy lists enterprise signature-based pricing as low as $0.001 per signature,
which is $1,000 per 1M signatures.

Source:

- [Privy pricing](https://www.privy.io/pricing)

Dynamic lists a $249/month Growth plan. Its pricing page includes one section
with 5,000 MAUs and $0.05 per additional MAU, and another wallet-infrastructure
section with 5,000/month and $0.05 per additional operation. Normalize Dynamic
carefully by workload before using it in public comparisons.

Source:

- [Dynamic pricing](https://www.dynamic.xyz/pricing)

OpenFort lists public plans from $99/month to $599/month, with 25,000 to
500,000 included monthly operations and extra operations priced from $0.008/op
to $0.004/op on paid plans. That overage range equals $4,000-$8,000 per 1M
operations on paid plans, and $10,000 per 1M operations on the free-plan
overage rate.

Source:

- [OpenFort pricing](https://www.openfort.io/pricing)

## Seams Cost Model

Use this as the starting model until benchmark data replaces it.

Assumed wallet operation:

- 4-10 Worker or service-binding calls;
- 4-10 Durable Object or storage coordination calls;
- 250-1,000 aggregate CPU ms across Router, Deriver, and SigningWorker roles;
- short-lived Durable Object activity;
- low write volume per operation;
- no long-lived websocket or always-on signer fleet in the baseline path.

Under those assumptions, Cloudflare direct infrastructure COGS should land near
$10-$50 per 1M wallet operations after optimization. A conservative early
deployment should still fit around $50-$200 per 1M operations once logging,
observability, retries, and inefficient protocol paths are included.

The exact number depends on:

- threshold signing CPU time;
- request fanout between Router, Deriver A, Deriver B, and SigningWorker;
- Durable Object active duration;
- state writes and storage layout;
- logging volume;
- geographic routing;
- retries and failed signing attempts.

## Estimated Advantage

Use the conservative range when making strategic decisions.

| Comparison | Factor using $10-$50/M Seams COGS | Factor using $50-$200/M Seams COGS |
| --- | ---: | ---: |
| Privy at $1,000/M signatures | 20x-100x | 5x-20x |
| OpenFort paid overage at $4,000-$8,000/M operations | 80x-800x | 20x-160x |
| OpenFort free overage at $10,000/M operations | 200x-1,000x | 50x-200x |
| Dynamic | Workload-dependent | Workload-dependent |

The safe external claim is "order-of-magnitude lower wallet infrastructure
cost." The stronger internal bet is that Seams can undercut signature-priced
wallet providers by 5x-10x while preserving high gross margin.

## Pricing Strategy

Wallets should be the wedge.

Seams can price embedded wallets aggressively because Cloudflare-native
deployment keeps direct infrastructure cost low:

- self-hosted wallet runtime: free or low fixed cost, with customers paying
  Cloudflare directly;
- hosted Seams wallet operations: target $0.0001-$0.00025/op, or $100-$250 per
  1M wallet operations;
- startup plan: include enough operations that early teams feel no hosting
  pressure;
- scale plan: undercut signature-priced wallet providers by 5x-10x;
- premium expansion: monetize policy engine, Commerce Harness, agent controls,
  risk rules, audit, and advanced deployment hardening.

This gives Seams a clear wedge:

```text
Cheap self-hostable threshold embedded wallets
  -> adoption and wallet volume
  -> policy engine usage
  -> Commerce Harness and agent execution
```

## Caveats

Public provider pricing is customer pricing, not competitor COGS. It includes
product surface, support, compliance, uptime, margin, and sales motion.

TEE-based systems can be cheap at small scale when they are simple and
centralized. They become more expensive operationally when production
redundancy, regional placement, attestation, enclave rollout, secret-release
policy, and incident recovery are included.

Self-hosted alternatives should be compared separately from managed hosted
plans. If a customer self-hosts another wallet stack, the comparison shifts from
provider price to operational burden, security properties, and infrastructure
complexity.

## Next Measurement

Replace the planning estimate with measured data:

1. Benchmark CPU ms for registration, presign, and signing paths.
2. Count Worker invocations, service-binding calls, Durable Object calls, and
   storage writes per operation.
3. Model costs at 100K, 1M, 10M, and 100M monthly wallet operations.
4. Include logging, retries, failed signing attempts, and regional routing.
5. Recompute hosted pricing floors after the measured COGS model lands.

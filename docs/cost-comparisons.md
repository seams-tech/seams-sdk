# Wallet Cost Comparisons

Date updated: June 27, 2026

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
| Postgres baseline being retired | $50/month fixed DB floor |
| Cloudflare D1 replacement | $0 incremental DB cost at early scale inside included limits |
| Privy enterprise signature floor | $1,000 per 1M signatures |
| OpenFort public overage range | $4,000-$10,000 per 1M operations |
| Dynamic public pricing | Workload-dependent; page includes MAU and operation-based sections |

## Public Pricing Anchors

Cloudflare Workers Standard includes 10M requests and 30M CPU ms each month on
the paid plan, then charges $0.30 per additional 1M requests and $0.02 per
additional 1M CPU ms. Durable Objects add 1M included requests, then $0.15 per
1M requests, plus duration pricing at $12.50 per 1M GB-s.

Cloudflare D1 is the planned replacement for the current Postgres baseline.
D1 uses scale-to-zero billing based on rows read, rows written, and storage.
On Workers Paid, the first 25B rows read, 50M rows written, and 5 GB stored are
included each month. Above that, D1 charges $0.001 per 1M rows read, $1.00 per
1M rows written, and $0.75 per GB-month stored.

Moving from the current $50/month Postgres database to D1 removes a fixed
$600/year database floor per environment before traffic. At early startup
volume, D1 should add $0 incremental database cost beyond the existing
Cloudflare deployment.

Sources:

- [Cloudflare Workers pricing](https://developers.cloudflare.com/workers/platform/pricing/)
- [Cloudflare Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/)
- [Cloudflare D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)

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
- D1 query shape, indexes, rows read, and rows written;
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

D1 adds a second cost advantage at startup scale: Seams can remove the fixed
Postgres database bill and keep database cost usage-based. For small teams, the
difference between a $50/month database and included D1 usage matters because it
keeps the first deployed wallet environment close to the Cloudflare Workers
baseline.

## Pricing Strategy

Wallets should be the wedge.

Seams can price embedded wallets aggressively because Cloudflare-native
deployment keeps direct infrastructure cost low:

- self-hosted wallet runtime: free or low fixed cost, with customers paying
  Cloudflare directly;
- D1-backed default persistence: eliminate the $50/month Postgres floor for
  early deployments;
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
3. Capture D1 `rows_read` and `rows_written` for the same paths.
4. Model costs at 100K, 1M, 10M, and 100M monthly wallet operations.
5. Include logging, retries, failed signing attempts, and regional routing.
6. Recompute hosted pricing floors after the measured COGS model lands.

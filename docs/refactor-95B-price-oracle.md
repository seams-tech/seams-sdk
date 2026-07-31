# Refactor 95B: Harden NEAR/USD Sponsorship Pricing

Date created: July 30, 2026

Status: proposed

## Decision

Replace the Ref Finance NEAR/USDC reserve ratio with the on-chain
`price-oracle.near` NEAR/USD feed.

The current Ref Finance integration calls `get_pool` and divides the USDC
reserve by the wrapped-NEAR reserve. That is a spot reserve ratio. Ref
Finance's exchange view contract exposes pool state but no cumulative-price or
TWAP query for this pool.

NEAR's oracle documentation now lists `price-oracle.near`. Its current
interface provides:

- a NEAR/USD feed backed by a median of multiple market sources;
- proactive on-chain updates every 30–60 seconds;
- a Pyth-compatible `get_price` view method with publication time;
- a Pyth-compatible `get_ema_price` view method;
- an explicit `get_price_no_older_than` staleness boundary.

Use the fresh multi-source median as the billable price. Use the EMA as a
deviation guard. This directly addresses a temporary bad venue or manipulated
AMM pool while keeping billing close to the executable market price.

Do not build a D1 price-history service in the first implementation.

## Why We Should Not Average Hourly Ref Finance Samples

An hourly reserve observation is not a true AMM TWAP. A true TWAP integrates a
price accumulator over elapsed on-chain time. Sampling the pool at predictable
hourly boundaries gives one instant observation the weight of the following
hour and lets an attacker target the known sampling time.

A 24-day window would also lag real market moves too far for sponsorship
admission and billing. This plan assumes the proposed window meant 24 hours.
Even a 24-hour sampled average remains a weaker primary source than a fresh
multi-venue median for this use case.

If an owned rolling price becomes necessary later, collect frequent,
independently sourced observations and treat the result as a sampled moving
average. Do not call it an on-chain Ref Finance TWAP.

## Research Basis

Research was reconciled on July 30, 2026:

- [NEAR oracle documentation](https://docs.near.org/primitives/oracles)
  lists the Outlayer oracle at `price-oracle.near` and the Pyth oracle at
  `pyth-oracle.near`.
- [Outlayer price-oracle documentation](https://price-oracle.outlayer.ai/docs/)
  states that `price-oracle.near` is proactively updated every 30–60 seconds,
  aggregates ten sources by median, and exposes fresh Pyth-compatible latest,
  EMA, and age-bounded view methods.
- [Ref Finance exchange views](https://github.com/ref-finance/ref-contracts/blob/main/ref-exchange/src/views.rs)
  expose `get_pool` and reserve information. They expose no price accumulator
  or TWAP view.
- [Pyth's NEAR integration documentation](https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/near)
  says Pyth Core support for NEAR ends on August 18, 2026. Do not add a new
  direct dependency on `pyth-oracle.near`.

The Outlayer feed has a different trust model from Ref Finance. It depends on
TEE workers, configured external venues, its push signers, contract governance,
and the NEAR RPC used to read it. The median removes dependence on one AMM
reserve ratio. It does not create a trustless DEX TWAP.

## Scope

This refactor owns the NEAR/USD conversion used by:

- NEAR gas-only sponsorship reservation;
- NEAR gas-only sponsorship settlement;
- EVM sponsorship where the current implementation converts native gas spend
  through the NEAR/USD market price.

The refactor does not change:

- gas estimation;
- finalized `tokens_burnt` accounting;
- spend-cap windows or policy semantics;
- prepaid balance or ledger semantics;
- attached-deposit treatment;
- Stripe billing;
- the Refactor 95 prewarm chain.

Refactor 95's prewarm heartbeat must remain free of D1 writes and external RPCs.
Price-oracle work must not be added to `/internal/prewarm`.

## Price Contract

Introduce one boundary-parsed oracle quote:

```ts
type NearUsdOracleQuote = {
  kind: 'accepted';
  usdNumerator: bigint;
  usdDenominator: bigint;
  publishTimeSeconds: number;
  source: 'outlayer_median';
  sourceVersion: string;
};
```

Raw NEAR RPC and contract responses must be parsed once into this type. Pricing
logic must not accept raw oracle records, decimal strings, optional timestamps,
or partially validated Pyth shapes.

The parser must:

1. require a positive integer price;
2. require a supported exponent and convert it to an exact bigint ratio;
3. require a positive publication time;
4. reject a future publication time beyond normal clock skew;
5. reject a quote older than 120 seconds;
6. reject arithmetic that exceeds the existing safe `spendMinor` boundary.

Keep all conversion arithmetic rational and integer-based. Round billable minor
units upward using the existing pricing rule.

## Admission And Settlement Rules

For each uncached market-price resolution:

1. read the latest NEAR/USD median from `price-oracle.near`;
2. read its EMA from the same contract;
3. parse both responses at the RPC boundary;
4. require both publications to be fresh;
5. compute the absolute latest-to-EMA deviation in basis points;
6. accept the latest median when deviation is at most 10%;
7. return `sponsorship_pricing_unavailable` when the deviation exceeds 10% or
   either response is stale or invalid.

The 10% threshold is a launch value. Before production deployment, replay at
least 30 days of NEAR/USD observations or run a staging observation period long
enough to confirm that ordinary volatility does not cause repeated rejection.
Change the threshold only with recorded evidence.

Continue using the existing short in-isolate cache to avoid duplicate RPC
reads within one request burst. The cached quote expires after at most 60
seconds and retains the exact publication time and oracle identity.

Reservation remains fail-closed when real pricing is unavailable. Settlement
keeps the current bounded behavior: if final price resolution fails, settle
against the already recorded reservation estimate and mark
`usedEstimatedFallback`. This ensures a completed sponsored transaction cannot
leave its reservation open because the oracle later became unavailable.

Every accepted quote must produce an auditable pricing version:

```text
outlayer:price-oracle.near:near-usd:<publish-time>:ema-guard-10pct
```

The sponsored-call record continues to store that version. Logs must contain
the publication age and deviation basis points. Logs must not influence
control flow.

## Configuration

Replace the Ref Finance provider shape with one exact real-pricing shape:

```json
{
  "provider": "outlayer",
  "nearRpcUrl": "https://free.rpc.fastnear.com",
  "oracleContractId": "price-oracle.near",
  "nearUsdPriceId": "c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750",
  "maxAgeSeconds": 120,
  "maxLatestToEmaDeviationBps": 1000,
  "cacheTtlMs": 60000,
  "near": {
    "TESTNET": {
      "nativeUnitDecimals": 24,
      "estimateFeeAmountYocto": "1000000000000000000000",
      "pricingVersionPrefix": "outlayer-near-testnet"
    }
  }
}
```

Validate this JSON once at worker startup. Required oracle identity, feed
identity, age, deviation, and cache fields stay required in the internal
configuration type.

Use the mainnet oracle for the market price in both deployment classes because
testnet NEAR gas is still accounted using the real NEAR/USD market price.

Retain static pricing as an explicitly selected development or emergency
provider. Do not silently switch from the real oracle to static pricing during
an admission request.

## Implementation Plan

### Phase 0: Verify The Live Contract

- [ ] Query `price-oracle.near` through the production NEAR RPC using
      `get_price`, `get_ema_price`, and `get_price_no_older_than`.
- [ ] Record the exact JSON response shapes, exponent, publication time, EMA
      semantics, and failure response for a stale or unknown feed.
- [ ] Confirm the documented NEAR/USD price identifier on the live contract.
- [ ] Observe update cadence and latest-to-EMA deviation in staging before
      freezing the 120-second and 10% launch limits.
- [ ] Stop this refactor if the live EMA has undocumented or unsuitable
      semantics. Use the multi-source median with freshness checks while the
      fallback design below is evaluated.

### Phase 1: Replace The Provider

Primary target:

- `packages/console-server-ts/src/sponsorship/pricing.ts`

Work:

- [ ] Delete the Ref Finance config, pool-response parser, reserve-ratio
      calculation, cache type, service constructor, and environment resolver.
- [ ] Add the narrow Outlayer config and accepted quote types.
- [ ] Add boundary parsers for the latest and EMA Pyth-compatible responses.
- [ ] Fetch both view methods concurrently through the existing NEAR JSON-RPC
      helper.
- [ ] Apply freshness and deviation checks before constructing a pricing quote.
- [ ] Reuse the accepted exact ratio for NEAR and EVM sponsorship conversion.
- [ ] Preserve existing estimate/finalize and integer rounding contracts.
- [ ] Export only the new provider names. Leave no Ref Finance compatibility
      branch or deprecated symbol.

### Phase 2: Deployment Configuration

Primary targets:

- `packages/console-server-ts/scripts/render-d1-gateway-config.mjs`
- generated staging and production Gateway configuration;
- `apps/web-server/README.md`;
- `docs/deployment/infra.md`.

Work:

- [ ] Replace `provider: "ref_finance"` and pool/token fields with the exact
      Outlayer configuration.
- [ ] Render the oracle contract, price identifier, staleness limit, deviation
      limit, and cache TTL explicitly.
- [ ] Remove obsolete Ref Finance examples and operator instructions.
- [ ] Keep the existing Gateway cron schedule unchanged. This provider is read
      on demand and does not require our heartbeat to refresh it.

### Phase 3: Focused Verification

Primary test:

- `tests/unit/sponsorship.realPricing.unit.test.ts`

Classify the existing Ref Finance fixtures as
`obsolete_test_or_fixture`: they verify the retired provider response rather
than a current user-facing invariant.

- [ ] Delete the Ref Finance RPC fixtures and assertions.
- [ ] Prove a fresh latest price within the EMA guard estimates and finalizes
      NEAR gas-only spend correctly.
- [ ] Prove EVM native gas conversion uses the same accepted NEAR/USD quote.
- [ ] Prove stale latest and stale EMA responses fail closed.
- [ ] Prove a latest-to-EMA deviation above 10% fails closed.
- [ ] Prove malformed price, exponent, timestamp, and feed responses are
      rejected at the boundary.
- [ ] Prove cache expiry causes a new oracle read and a cached quote retains
      its original publication version.
- [ ] Prove settlement falls back to the reservation estimate after a later
      oracle failure.
- [ ] Run the single unit file first.
- [ ] Run the focused relayer coverage for capped NEAR reservation and
      settlement because the public sponsorship behavior is shared.

### Phase 4: Deploy And Observe

- [ ] Deploy one coherent backend revision to staging.
- [ ] Confirm pricing metadata names `price-oracle.near` and the exact
      publication time.
- [ ] Compare accepted latest prices with Ref Finance spot prices for
      observation only during the staging period.
- [ ] Alert on stale quotes, EMA-guard rejection, invalid responses, and
      estimated settlement fallback.
- [ ] Confirm no pricing job or external RPC was added to the Refactor 95
      prewarm route.
- [ ] Deploy the same revision to production.
- [ ] Delete temporary Ref Finance comparison instrumentation after the
      observation period.

## Contingency: Owned Sampled Average

Implement this only if Phase 0 shows that the Outlayer contract is unsuitable
or its operational trust boundary is unacceptable.

The fallback is a small Gateway-owned D1 observation store driven by a
dedicated five-minute cron expression. It must remain separate from the
one-minute prewarm chain.

Requirements:

- collect at least two independent sources, one of which may be Ref Finance;
- key observations by source, source version or block, and observation time;
- reject stale, duplicate, zero-liquidity, and malformed observations;
- require source quorum before publishing an accepted price;
- use a rolling 24-hour window with a documented piecewise-constant
  time-weight calculation;
- require adequate window coverage and a maximum gap between observations;
- persist the computed quote and its complete input range for audit;
- fail closed for new reservations when coverage or quorum is missing;
- prune observations only after the audit retention period;
- jitter source reads or otherwise prevent one known instant from representing
  a complete interval.

Five-minute sampling yields at most 289 boundary observations for a 24-hour
calculation. That is small enough for a direct indexed D1 query. Do not add a
framework, Durable Object, queue, separate Worker, or 24-day hot-path window.

This fallback remains a sampled moving average. It does not become a true Ref
Finance TWAP unless the AMM itself exposes a reviewed cumulative-price
primitive.

## Acceptance

Refactor 95B is complete when:

1. sponsorship pricing no longer consumes the Ref Finance pool reserve ratio;
2. every real NEAR/USD quote comes from a fresh, boundary-parsed
   `price-oracle.near` multi-source median;
3. the latest price is rejected when it exceeds the accepted EMA deviation;
4. reservation fails closed on unavailable pricing and completed settlement
   uses its recorded estimate when final resolution fails;
5. pricing records identify the oracle contract and publication time;
6. Ref Finance provider code, configuration, fixtures, and documentation are
   deleted;
7. the prewarm heartbeat still performs no D1 writes or external RPCs;
8. staging shows acceptable availability before production rollout.


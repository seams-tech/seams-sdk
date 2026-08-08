# Refactor 95B: Harden NEAR/USD Sponsorship Pricing

Date created: July 30, 2026

Status: implemented locally; staging and production rollout pending

## Decision

Replace the Ref Finance NEAR/USDC reserve ratio with the on-chain
`price-oracle.near` NEAR/USD feed.

The Ref Finance integration divided the USDC reserve by the wrapped-NEAR
reserve returned by `get_pool`. That value was a spot reserve ratio. A
temporary reserve imbalance could therefore affect sponsorship admission and
billing.

The new provider reads Outlayer's latest multi-source price and EMA from
`price-oracle.near`. The latest value is used for pricing when both values are
fresh and their deviation is within the configured limit. This directly
addresses temporary venue spikes without adding a price-history subsystem.

## Live Contract Verification

The contract ABI was checked on July 30, 2026 through:

- `https://free.rpc.fastnear.com`;
- `https://rpc.mainnet.near.org`.

The verified calls are:

- `get_price` with `{"price_identifier":"<64-character price id>"}`;
- `get_ema_price` with `{"price_id":"<64-character price id>"}`.

The EMA argument name differs from the latest-price argument name.

At verification time, both RPCs returned JSON `null` for the configured
NEAR/USD identifier
`c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750`.
`get_price_data` also returned a record whose `price` field was `null`.

This is a production rollout blocker. With the implemented fail-closed
behavior, capped sponsorship admission will return
`sponsorship_pricing_unavailable` until the feed publishes usable latest and
EMA values. Staging must confirm a live, fresh feed before production receives
this configuration.

## Price Contract

The provider accepts the Pyth-compatible price fields only after boundary
validation:

1. `price` is a positive safe integer;
2. `expo` is an integer between -36 and 36;
3. `publish_time` is a positive safe integer;
4. publication time is no more than 30 seconds in the future;
5. latest and EMA publication ages are within `maxAgeSeconds`;
6. latest-to-EMA deviation is within
   `maxLatestToEmaDeviationBps`.

Price conversion uses exact bigint ratios. Existing spend-minor rounding and
safe-integer enforcement remain unchanged.

The pricing version records the source and publication:

```text
outlayer:price-oracle.near:near-usd:<publish-time>:ema-guard-<bps>bps
```

## Admission and Settlement

Each uncached resolution concurrently reads the latest and EMA contract
methods. The latest price is accepted after freshness and deviation checks.
The short in-isolate cache retains the exact ratio and pricing version for up
to `cacheTtlMs`.

New reservation remains fail-closed when live pricing is unavailable.
Completed settlement retains the existing bounded behavior: a failed final
price resolution settles against the recorded reservation estimate and marks
the estimated fallback.

The same accepted NEAR/USD quote serves:

- NEAR gas-only sponsorship reservation and settlement;
- existing EVM native-gas conversion through the shared market-price path.

## Configuration

`SPONSORED_EXECUTION_REAL_PRICING_JSON` now has one real-provider shape:

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

Invalid non-empty real configuration fails startup validation. Static pricing
remains an explicitly selected development or emergency provider. Runtime
oracle failures never select static pricing automatically.

## Implemented Changes

### Provider

- [x] Deleted the Ref Finance config, pool parser, reserve-ratio calculation,
      service constructor, resolver, and exports.
- [x] Added the narrow Outlayer config and provider.
- [x] Added boundary parsing for NEAR RPC byte responses and price fields.
- [x] Added fresh latest and EMA reads with an exact bigint deviation check.
- [x] Reused the accepted quote for NEAR and EVM conversion.
- [x] Preserved estimate, finalize, cache, and rounding contracts.
- [x] Removed all Ref Finance compatibility symbols and branches.

### Deployment and Documentation

- [x] Updated the D1 Gateway renderer and checked-in example.
- [x] Updated staging script fixtures.
- [x] Updated web-server and infrastructure documentation.
- [x] Left Refactor 95 prewarm behavior unchanged.

### Verification

The former Ref Finance fixtures were classified as
`obsolete_test_or_fixture` because they encoded the retired provider response.
They were replaced with current provider behavior.

- [x] Fresh latest and EMA values price NEAR estimate and finalization.
- [x] EVM gas pricing uses the accepted NEAR/USD quote.
- [x] The cache avoids duplicate oracle reads.
- [x] Real configuration takes precedence over explicitly configured static
      pricing.
- [x] Null, stale, excessive-deviation, and malformed responses fail closed.
- [x] Unconfigured chain rules fail closed.
- [ ] Staging observes a live feed and acceptable availability.
- [ ] Production deploy completes after the staging gate.

## Why We Do Not Sample Ref Finance Hourly

An hourly reserve observation is a sampled spot price. A true AMM TWAP
integrates a cumulative price over elapsed on-chain time. Predictable hourly
sampling lets one instant represent the following hour and creates a
manipulable sampling boundary.

A 24-day window would lag market movements too far for sponsorship admission
and billing. A future owned moving average should sample multiple independent
sources frequently, enforce quorum and coverage, and remain separate from the
one-minute prewarm route.

## Acceptance

The code portion is complete when:

1. sponsorship pricing has no Ref Finance reserve-ratio path;
2. real NEAR/USD quotes come from fresh, boundary-parsed
   `price-oracle.near` latest and EMA values;
3. excessive latest-to-EMA deviation fails closed;
4. completed settlement can use its recorded estimate after a later oracle
   failure;
5. pricing records identify the oracle contract and publication time;
6. provider code, configuration, fixtures, and documentation contain no
   retired Ref Finance path.

The rollout is complete after staging confirms a live feed and production
deploys the same coherent revision.

## Sources

- [NEAR oracle documentation](https://docs.near.org/primitives/oracles)
- [Outlayer price-oracle documentation](https://price-oracle.outlayer.ai/docs/)
- [Ref Finance exchange views](https://github.com/ref-finance/ref-contracts/blob/main/ref-exchange/src/views.rs)
- [Pyth NEAR integration documentation](https://docs.pyth.network/price-feeds/core/use-real-time-data/pull-integration/near)

# Dropped / Replaced EVM Transactions

## Problem Summary

In EVM networks, a transaction hash can be accepted by one RPC endpoint and later become unavailable in `eth_getTransactionByHash` or never appear consistently across backends. This can happen due to mempool eviction, backend divergence, replacement, underpriced fees, or node restarts.

The prior user-facing failure mode was a freeze at "waiting for finalization" when the client did not classify some disappearance patterns as terminal.

## Root Cause Categories

1. Replacement or nonce contention.
   The account nonce advances beyond the tx nonce, which means another tx consumed that nonce.
2. Hash disappeared after broadcast.
   The tx hash is no longer visible to the polling RPC pending view.
3. Underpriced fee caps.
   `maxFeePerGas` is persistently below observed base fee.
4. RPC/backend divergence.
   Different backends disagree on pending pool contents.
5. Node restart or mempool churn.
   Pending entries are lost and hash lookups intermittently fail.

## Current EVM Client Handling

Location: `client/src/core/rpcClients/evm/publicClient.ts` (`waitForTransactionReceipt`).

Terminal branches now emitted:

1. `dropped_nonce_advanced`
   Trigger: `latestNonce > txNonce` sustained and tx/receipt do not confirm original transaction.
   Error shape: `code=tx_dropped_or_replaced`, `reason=dropped`.
2. `dropped_hash_disappeared` (dropped)
   Trigger: tx was seen, then disappears while pending/latest nonce checks indicate it is not advancing.
   Error shape: `code=tx_dropped_or_replaced`, `reason=dropped`.
3. `dropped_hash_disappeared` (replaced)
   Trigger: tx hash disappears and `pendingNonce > txNonce` for sustained polls.
   Error shape: `code=tx_dropped_or_replaced`, `reason=replaced`.
4. `underpriced_fee`
   Trigger: sustained `baseFeePerGas > maxFeePerGasHint`.
   Error message instructs caller to re-sign with refreshed fee caps.
5. `timeout`
   Trigger: no terminal evidence before deadline.

## Important Nuance

`tx hash disappeared` is usually an external mempool/RPC event, not a signing bug by itself.

The freeze was a client handling bug: one disappearance + nonce-pattern path was previously not classified as terminal and could wait until timeout. That gap is now closed.

## UI / Integration Behavior

The demo now uses a shared transaction handler (`examples/tatchi-site/src/flows/demo/hooks/demoEvmTransactionHandling.ts`) for Tempo + ARC EVM send flows:

1. Shared finalization wait path.
   `waitForDemoEvmFinalization` centralizes abort + timeout wiring and finalization branch debug emission.
2. Click-time fee refresh.
   `resolveClickTimeEip1559FeeCaps` refreshes fee caps right before request assembly, while preserving fallback to cached/default caps.
3. Non-blocking failure reporting.
   `reportDemoEvmBroadcastFailure` schedules nonce-lane reporting/reconciliation off the UI critical path so loading spinners/toasts cannot deadlock on reporting latency.

This keeps finalization UX terminal even when nonce-lane bookkeeping is slow.

## What Is Still Intentionally Ambiguous

If RPC signals are contradictory and do not sustain any dropped/replaced or underpriced branch, the client returns `timeout` rather than guessing.

This is intentional to avoid false positives.

## Operational Guidance

1. Treat `tx_dropped_or_replaced` as a terminal send outcome.
2. For `reason=replaced`, re-query nonce state and surface replacement guidance to the user.
3. For `underpriced_fee`, refresh EIP-1559 fee caps and re-sign.
4. For `timeout`, retry with another RPC backend or perform explicit nonce-lane reconciliation.
5. If UI is already unblocked but bookkeeping is still reconciling, wait for reconciliation completion before high-frequency re-send loops on the same lane.

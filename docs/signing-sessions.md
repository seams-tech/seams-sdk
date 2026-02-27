# Threshold Signing Warm Sessions

Last updated: 2026-02-27

## 1. Core Contract

1. Login performs one passkey assertion and uses that single `PRF.first` derivation to warm all enabled threshold signers.
2. In current default config, login warms `ed25519` and `ecdsa` together, with `ecdsa` depending on `ed25519`.
3. Tempo/EVM sign flows must not trigger hidden bootstrap as a normal path; they consume already-warm session state or use explicit reconnect flow.
4. Confirmer UI must open immediately; network-dependent preparation is hydrated after mount.

## 2. One-Touch Warmup Architecture

Primary implementation:

- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts`
- `client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts`

Current login warm path:

1. `loginAndCreateSession(...)` decides whether warmup is required (threshold mode with non-zero TTL and remaining uses).
2. `maybeWarmThresholdSigningSessions(...)` loads threshold key material and clears stale warm session state.
3. `primeThresholdLoginWarmSigners(...)` builds signer tasks and runs them via dependency graph.
4. `ed25519` task calls `connectEd25519Session(...)`:
   - prompts passkey once,
   - extracts `PRF.first`,
   - caches `PRF.first` in passkey worker by `sessionId`,
   - mints session JWT,
   - derives and returns `ecdsaClientVerifyingShareB64u`.
5. `ecdsa` task calls `bootstrapEcdsaSession(...)` with:
   - `sessionId` and `authorizationJwt` from the `ed25519` task,
   - `clientVerifyingShareB64u` from the same passkey derivation.
6. Login requires `getWarmSigningSessionStatus(...)` to return `active`; otherwise login fails closed.

## 3. Enabled Signers and Dependency Graph

The warm planner already supports a signer set (`signersToWarm`) and dependency execution:

1. Defaults to `['ed25519', 'ecdsa']`.
2. Rejects invalid graph requests (`ecdsa` without `ed25519`).
3. Executes dependency-ready tasks in parallel (`Promise.all`) for future plug-n-play signers.

This is the canonical place to extend when more signer families become configurable.

## 4. Confirmer UX Contract (No Pre-Modal Blocking)

Primary implementation:

- `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
- `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
- `client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts`
- `client/src/core/signingEngine/touchConfirm/intentDigestPreparationRegistry.ts`

Required behavior:

1. Start intent preparation and managed nonce reservation in background.
2. Open confirmer immediately with pending digest placeholders.
3. Hydrate title/body/model/challenge after preparation resolves.
4. Keep confirm action loading/disabled until hydration is complete.

Do not block modal mount on:

1. RPC calls (nonce fetch, block/receipt reads, fee reads).
2. Intent building and digest generation.
3. Threshold key reconnect checks.
4. Presign handshake/refill.

## 5. Finalization Polling Issues to Watch

Finalization bugs are usually post-broadcast issues, not signing failures.

1. RPC request timeout only is insufficient; response body parsing can also hang. Bound both request and response parsing by deadline.
2. `eth_getTransactionReceipt` can return `null` for long periods even when tx is known; enforce explicit finality deadline and useful error surface.
3. Underpriced pending transactions can look like stuck finalization. Compare `maxFeePerGas` hint against latest base fee and fail with explicit retry guidance when persistently underpriced.
4. On Tempo flows, receipt polling alone can be noisy; keep state-based confirmation fallback (for example, expected contract state change) where available.
5. Reset per-attempt UI state before each flow start so stale tx-hash metadata is never shown on a new transaction.

## 6. Nonce Issues to Watch

Primary implementation:

- `client/src/core/rpcClients/evm/nonceManager.ts`
- `client/src/core/signingEngine/api/evmSigning.ts`

Critical rules:

1. Always reserve nonce before signing and commit only after successful broadcast.
2. Always release reservation on sign/broadcast failure or user cancellation.
3. On nonce-conflict broadcast errors, map to retryable typed error and refresh nonce state from chain.
4. Keep nonce scope concrete and deterministic: `chain + networkKey + chainId + sender (+ nonceKey for tempo)`.
5. Fail closed on ambiguous/misconfigured chain routing; do not guess network mapping.
6. Do not reintroduce caller-managed nonce injection as default behavior.

## 7. Regression Checklist

1. Login warmup with threshold mode enabled results in one TouchID prompt and active warm session.
2. EVM and Tempo signer confirms open immediately while nonce/intent work continues in background.
3. Second transaction in the same UI flow never shows previous tx hash in loading toast.
4. Broadcast reporting always calls success/failure hooks so nonce reservations cannot leak.
5. Finalization wait always terminates with either confirmed state or typed timeout/underpriced guidance.

# Threshold Signing Warm Sessions

Last updated: 2026-02-28

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

Current unlock warm path:

1. `auth.unlock(...)` decides whether warmup is required (threshold mode with non-zero TTL and remaining uses).
2. `maybeWarmThresholdSigningSessions(...)` loads threshold key material and clears stale warm session state.
3. `primeThresholdLoginWarmSigners(...)` builds signer tasks and runs them via dependency graph.
4. `ed25519` task calls `connectEd25519Session(...)`:
   - prompts passkey once,
   - extracts `PRF.first`,
   - caches `PRF.first` in passkey worker by `sessionId`,
   - mints session JWT,
   - derives and returns `ecdsaHssClientRootShare32B64u`.
5. `ecdsa` task calls `bootstrapEcdsaSession(...)` with:
   - `sessionId` and `authorizationJwt` from the `ed25519` task,
   - `clientRootShare32B64u` from the same passkey derivation.
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

1. Always reserve nonce before signing and transition lifecycle explicitly (`markBroadcastAccepted` -> `markFinalized|markDroppedOrReplaced`).
2. Always mark reservation rejected on sign/broadcast failure or user cancellation.
3. On nonce-conflict or blocked-lane broadcast errors, map to retryable typed error and reconcile lane state from chain.
4. Keep nonce scope concrete and deterministic: `chain + networkKey + chainId + sender (+ nonceKey for tempo)`.
5. Fail closed on ambiguous/misconfigured chain routing; do not guess network mapping.
6. Do not reintroduce caller-managed nonce injection as default behavior.

## 7. Regression Checklist

1. Login warmup with threshold mode enabled results in one TouchID prompt and active warm session.
2. EVM and Tempo signer confirms open immediately while nonce/intent work continues in background.
3. Second transaction in the same UI flow never shows previous tx hash in loading toast.
4. Broadcast reporting always calls lifecycle hooks (`accepted`/`rejected`/`finalized`/`dropped|replaced`) so nonce lanes cannot drift silently.
5. Reconcile surfaces unresolved nonce gaps deterministically and dropped/replaced transitions recover lane progress.
6. Finalization wait always terminates with either confirmed state or typed timeout/underpriced guidance.

## 8. Sealed Refresh (`sealed_refresh_v1`) Integration

Use this only when the server-side PRF seal module is enabled.

Client config (opt-in):

```ts
const tatchi = createTatchiPasskey({
  signingSessionPersistenceMode: 'sealed_refresh_v1',
  signingSessionSeal: {
    keyVersion: 'kek-s-2026-02',
    shamirPrimeB64u: '<base64url-prime-no-padding>',
  },
});
```

Requirements:

1. `signingSessionSeal.shamirPrimeB64u` must be valid base64url without padding.
2. Server exposes authenticated PRF seal routes:
   - `POST /threshold-ecdsa/prf-seal/apply-server-seal`
   - `POST /threshold-ecdsa/prf-seal/remove-server-seal`
3. Wallet iframe and touchConfirm worker run under wallet origin with sessionStorage available.

Key material generation:

1. Run `pnpm prf-seal:keygen` from the repo root.
2. Copy server outputs into relay env:
   - `PRF_SESSION_SEAL_KEY_VERSION`
   - `SHAMIR_P_B64U`
   - `SHAMIR_E_S_B64U`
   - `SHAMIR_D_S_B64U`
3. Copy client outputs into app env:
   - `VITE_SIGNING_SESSION_PERSISTENCE_MODE=sealed_refresh_v1`
   - `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`
   - `VITE_SIGNING_SESSION_SHAMIR_P_B64U`

Behavior:

1. Same-tab refresh rehydrates from sealed session record and avoids an extra TouchID prompt.
2. New tab/window still requires TouchID (sessionStorage scope is per-tab).
3. If sealed record is missing/expired/exhausted/invalid, flow fails closed and requests normal re-auth.

Operational guidance:

1. Keep default mode as `none`; enable `sealed_refresh_v1` per app or per cohort.
2. Monitor sealed apply/remove failure rates before broad rollout.
3. Runtime is lazy-loaded only when `sealed_refresh_v1` is enabled.

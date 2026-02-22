# Threshold ECDSA Timings

Last updated: 2026-02-22

## 1. Trace Summary

The measured slow path is dominated by the presign handshake (`/threshold-ecdsa/presign/step`), not by bootstrap/authorize/sign endpoints.

From the provided server logs:

1. Bootstrap and auth:
- `/threshold-ecdsa/bootstrap`: `18ms`
- `/threshold-ecdsa/authorize`: `9ms`

2. Foreground signing presign handshake:
- `/threshold-ecdsa/presign/init`: `34ms`
- `/threshold-ecdsa/presign/step` durations:
  - `767ms`
  - `775ms`
  - `1087ms`
  - `1136ms`
  - `1119ms`
  - `1133ms`
- Presign total (init + steps): `6051ms`

3. Foreground sign endpoints:
- `/threshold-ecdsa/sign/init`: `9ms`
- `/threshold-ecdsa/sign/finalize`: `24ms`

4. Foreground server-total:
- Authorize + presign + sign endpoints: `6093ms`
- Including bootstrap: `6111ms`

## 2. Why First Tx Feels ~12s

After signature finalize, the client schedules post-sign refill to top up the presign pool. That refill is another presign handshake and has similar cost (~5-6s).

So first transaction window often looks like:

1. Foreground cold sign: ~6s server-side.
2. Immediate background refill: ~5-6s server-side logs.

This matches the observed "about 12 seconds" log window.

## 3. Expected vs Unexpected

This behavior is expected with current design:

1. Cold first sign requires one full presign handshake when the client pool depth is 0.
2. Subsequent signs are faster when a pooled presignature is available.
3. Extra post-sign `/presign/step` logs are refill traffic, not duplicate foreground signing.

Recent fix note:

- Commit-start refill is now skipped on true cold-start (depth 0), so the client no longer runs duplicate concurrent presign handshakes for the same foreground sign.

## 4. Cache Behavior Today

Current caching layers:

1. Canonical threshold-ECDSA session record:
- Stored in memory and `sessionStorage` (not IndexedDB).
- File: `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`

2. ECDSA auth-session policy/JWT:
- In-memory map (not IndexedDB).
- File: `client/src/core/signingEngine/threshold/session/ecdsaAuthSession.ts`

3. Client presign pool:
- In-memory map only (not persisted).
- File: `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`

Implication:

- If runtime memory is lost (refresh/new tab/new process), presign pool depth resets to 0 and the next sign is cold again.

## 5. Does Login Always Pay Cold Sign?

Not always, but usually after a fresh runtime.

1. In `threshold-signer` warm mode, login does bootstrap a threshold ECDSA session.
2. Bootstrap does not precompute and persist client presignatures.
3. Presign pool is memory-only, so it is not recovered from IndexedDB.

If the same runtime stays alive and pool entries remain, next sign can stay warm. After refresh/restart, it is cold again.

## 6. IndexedDB Caching Option

Local caching in IndexedDB is possible in principle, but not currently implemented.

Caution:

1. Presign entries include sensitive one-time signing-share material (`kShare`, `sigmaShare`).
2. Persisting them at rest increases local secret exposure and requires strict lifecycle controls (encryption, integrity, expiry, single-use deletion, crash-safe consume semantics).

Safer speed-up options before IndexedDB persistence:

1. Keep presign pool memory-only, but prefill in background immediately after login warm-up.
2. Tune pool policy conservatively (for example `targetDepth=1`, `lowWatermark=0`, `maxRefillInFlight=1`) to reduce churn.
3. Continue measuring per-route durations to verify whether latency is network/compute/store bound.

## 7. Code References

1. Client cold-start refill guard:
- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`

2. Client presign pool map and scheduler:
- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`

3. Express timing logs (`durationMs`):
- `server/src/router/express/routes/thresholdEcdsa.ts`

4. Login warm bootstrap path:
- `client/src/core/TatchiPasskey/login.ts`


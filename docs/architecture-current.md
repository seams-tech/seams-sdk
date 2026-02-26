# Architecture Current

Last updated: 2026-02-22
Status: Prototype baseline

## 1. System Shape

The system has three execution domains:

1. Main thread SDK/runtime (or wallet-iframe client router)
2. `passkey-confirm` worker (confirmation orchestration + secure flow control)
3. Signer workers (`near-signer`, `eth-signer`, `tempo-signer`) for cryptographic execution

Main thread initiates intents and renders UI, but sensitive signing/export orchestration is worker-owned.

## 1.1 Chain Identity Contract

Chain naming is split into family vs concrete network:

- family: `near` | `tempo` | `evm`
- network examples:
  - NEAR: `near-mainnet`, `near-testnet`
  - Tempo: `tempo-mainnet`, `tempo-testnet`
  - EVM: `arc-mainnet`, `arc-testnet`, `ethereum-mainnet`, `ethereum-sepolia`

Runtime behavior selection uses family. Concrete routing/state (RPC, explorer, nonce scope) uses network and chainId.

## 2. Confirmation and Signing Model

Threshold ECDSA (Tempo/EVM) uses a two-phase flow:

1. `prepare + tx confirmer` can run concurrently
2. `commit/sign` is serialized per account

This gives responsive UX (multiple confirmers can appear) while preserving commit safety.

## 3. Threshold ECDSA State Ownership

Threshold key/session data is canonicalized through one ownership path:

- written by explicit provisioning flows (login/registration/manual reconnect)
- read by signing flows
- no silent fallback to legacy/stale key/session shapes

If required threshold session material is missing or stale, the flow fails closed with typed reconnect guidance.

## 4. Commit Queue Semantics

Per-account threshold commit queue rules:

- scope: same `nearAccountId`
- ordering: FIFO by commit enqueue time
- queue covers commit/sign stage only
- cancellation before commit start drops queued work
- typed queue errors: `commit_queue_overflow`, `commit_queue_timeout`, `cancelled`

Cross-account commits remain concurrent.

## 5. Presign Pool Model

Presign pool is actively managed (no legacy passive-only mode):

- refill scheduling on low-watermark and post-success top-up
- per-pool refill in-flight dedupe
- refill is best-effort and non-blocking for active user sign
- policy source: local defaults + optional server hint (clamped by client bounds)

## 5.1 Presign Flow (Detailed)

1. Authorize:

- signer calls `/threshold-ecdsa/authorize`
- response may include an advisory `presignPoolPolicy` hint

2. Commit start scheduling:

- secp signer schedules refill with trigger `commit_start`
- scheduler only queues refill when depth is at/below `lowWatermark`

3. Sign execution:

- sign path pops one client presign entry for the current pool key
- if empty, it runs presign handshake inline (`presign/init` + `presign/step`) and uses that entry
- sign path calls `/threshold-ecdsa/sign/init` with the chosen `presignatureId`
- relayer reserves that exact presign record (`reserveById`)
- sign finalization completes via `/threshold-ecdsa/sign/finalize`

4. Fallback and safety:

- if sign init reports `pool_empty`, client generates a new presign entry and retries sign init once
- refill failure does not fail the active sign request

5. Post-sign top-up:

- after successful sign, scheduler runs with trigger `post_sign_success`
- target is to refill toward `targetDepth`

## 5.2 Client Pool Storage

Client presign pool is runtime memory only:

- module: `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- storage: `Map<string, ThresholdEcdsaClientPresignatureShare[]>`
- refill in-flight tracking: `Map<string, Promise<void>>`

Pool key fields:

- `relayerUrl`
- `relayerKeyId`
- `clientVerifyingShareB64u`
- normalized `participantIds`

Persistence behavior:

- process-local only
- cleared on runtime reset/reload/new process
- no cross-tab/device sharing

## 5.3 Server Pool Storage

Server stores relayer-side presign material in persistent backend stores selected by server config:

- Cloudflare Durable Objects
- Upstash Redis REST
- Redis TCP
- Postgres
- in-memory (dev/local fallback only)

All variants expose shared semantics:

- `put`: write available presign record
- `reserve`/`reserveById`: move available -> reserved atomically
- `consume`: one-time removal on successful finalize
- `discard`: remove reserved entry on failure/abort paths

In current sign flow, client-provided `presignatureId` is used, so server path is `reserveById` (not arbitrary pick).

## 5.4 Policy Resolution and Defaults

Default client policy:

- `enabled: true`
- `targetDepth: 3`
- `lowWatermark: 1`
- `maxRefillInFlight: 1`
- `refillAttemptTimeoutMs: 30000`

Scope semantics:

- `targetDepth` and `lowWatermark` apply per pool key (`relayerUrl + relayerKeyId + clientVerifyingShareB64u + participantIds`), which is effectively per account/credential context.
- `maxRefillInFlight` is a runtime-global cap across pool keys within one client runtime/tab/process.

Resolution order:

1. local client config (`thresholdEcdsaPresignPool`)
2. server authorize hint (`presignPoolPolicy`)
3. client clamp/normalization bounds

Client clamps protect runtime safety:

- `targetDepth`: 1..64
- `lowWatermark`: 0..`targetDepth`
- `maxRefillInFlight`: 1..8
- `refillAttemptTimeoutMs`: 5000..120000

## 5.5 Operational Footguns

- In-memory server pool in multi-instance deployments causes split state and intermittent `pool_empty`/session misses.
- Mixed backend kinds or mismatched prefixes across relayer instances split pools.
- Extremely high target depth increases presign churn because presign generation is currently `count=1` per session.

See `docs/presigning-pool.md` for deeper operational notes.

## 6. Key Export Model

Single canonical export API:

`exportKeypairWithUI(nearAccountId, { chain: 'near' | 'evm' | 'tempo', variant?, theme? })`

Chain mapping:

- `near` -> Ed25519 export
- `evm` -> secp256k1 export
- `tempo` -> secp256k1 export

`evm` and `tempo` currently map to the same underlying secp256k1 export material; chain changes caller intent and UI labeling.

Export is worker-owned (`EXPORT_PRIVATE_KEYS_WITH_UI` path). Main thread does not orchestrate secure intermediate export steps or parse PRF output.

## 7. Wallet-Iframe Parity

Wallet and non-wallet runtimes follow equivalent behavior for:

- export request handling (`PM_EXPORT_KEYPAIR_UI`)
- signing overlay lifecycle
- typed error mapping

## 8. Security and Correctness Invariants

- no duplicate legacy codepaths for old export/sign queue behavior
- no hidden bootstrap side effects inside normal sign calls
- no secret leakage via public API response payloads
- signer/confirm worker boundaries remain explicit and test-guarded

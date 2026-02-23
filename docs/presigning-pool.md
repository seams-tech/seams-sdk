# Threshold ECDSA Presigning Pool and Signing Lifecycle

Last updated: 2026-02-23

## 1. Scope

This document covers the full lifecycle of threshold ECDSA signing in this repo:

1. Session/bootstrap and authorize
2. Foreground transaction signing (pool hit vs cold miss)
3. Background presign pool refill
4. Timing profile from observed logs
5. Security and secrecy requirements for presign artifacts

Terminology used below:

- Foreground sign: the user-initiated sign operation that must return a signature now.
- Presign pool refill: background generation of future presignatures.
- Presignature: one-time Cait-Sith preprocessing material identified by `presignatureId`.

## 2. End-to-End Lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant C as Client (wallet/signer)
    participant A as Relayer /authorize
    participant P as Relayer /presign/*
    participant S as Relayer /sign/*
    participant CP as Client Presign Pool
    participant SP as Server Presign Pool

    U->>C: Click "Sign transaction"
    C->>A: POST /threshold-ecdsa/authorize
    A-->>C: mpcSessionId

    C->>CP: pop presignature
    alt Pool hit
        CP-->>C: presignatureId + (bigR, kShare, sigmaShare)
    else Pool miss (cold)
        C->>P: POST /threshold-ecdsa/presign/init
        loop handshake rounds
            C->>P: POST /threshold-ecdsa/presign/step
            P-->>C: outgoing + stage/event
        end
        P->>SP: store relayer presign share (available)
        C-->>C: keep client presign share (memory)
    end

    C->>S: POST /threshold-ecdsa/sign/init (with presignatureId)
    S->>SP: reserve presignature
    S-->>C: signingSessionId + entropy (+bigR)

    C->>S: POST /threshold-ecdsa/sign/finalize (client signature share)
    S->>SP: consume reserved presignature
    S-->>C: signature65

    par Background refill (best effort)
        C->>P: /presign/init + /presign/step loop
        P->>SP: add available presignature
        C->>CP: push client presignature
    and User flow continues
        C-->>U: Signed tx returned
    end
```

## 3. Which Operations Are Presign vs Actual Tx Signing

| Operation | Class | Endpoint(s) | Purpose |
|---|---|---|---|
| Threshold session bootstrap | Session/Auth | `/threshold-ecdsa/bootstrap` | Create threshold session + token/cookie binding |
| Sign authorization | Session/Auth | `/threshold-ecdsa/authorize` | Mint/consume short-lived MPC session id (`mpcSessionId`) |
| Presign init | Presign (Cait-Sith preprocessing) | `/threshold-ecdsa/presign/init` | Start one presignature handshake |
| Presign step | Presign (Cait-Sith preprocessing) | `/threshold-ecdsa/presign/step` | Advance triples/presign rounds until `presign_done` |
| Sign init | Actual tx signing | `/threshold-ecdsa/sign/init` | Bind digest + presignature and get relayer round-1 data |
| Sign finalize | Actual tx signing | `/threshold-ecdsa/sign/finalize` | Combine shares and return final 65-byte signature |

Important: `/presign/*` is preprocessing, not the final transaction signature itself.

## 4. Timing Profile (Observed)

Measured from your recent server logs.

| Operation | Class | Typical server duration |
|---|---|---|
| `/threshold-ecdsa/bootstrap` | Session/Auth | ~18ms |
| `/threshold-ecdsa/authorize` | Session/Auth | ~4-10ms |
| `/threshold-ecdsa/presign/init` | Presign | ~20-35ms |
| `/threshold-ecdsa/presign/step` (normal) | Presign | ~740-1150ms per step |
| `/threshold-ecdsa/presign/step` (under contention) | Presign | ~1800-2300ms per step |
| `/threshold-ecdsa/sign/init` | Actual signing | ~7-10ms |
| `/threshold-ecdsa/sign/finalize` | Actual signing | ~24-35ms |

Cold foreground sign usually includes one full presign handshake:

- 1 x `presign/init`
- about 6 x `presign/step` in observed traces
- then `sign/init` + `sign/finalize`

So cold path is usually dominated by presign steps (often several seconds).

## 5. Why Logs Continue After Signature Is Returned

Yes, those post-sign `/presign/*` logs are typically background refill.

Current signer behavior:

1. On commit start: may schedule refill if pool depth and policy trigger it.
2. On sign success: schedules refill again toward target depth.
3. Refill runs asynchronously and can continue after the user already got the signature.

Current defaults are aggressive for refill depth:

- `targetDepth: 20`
- `lowWatermark: 5`
- `maxRefillInFlight: 2`

With these defaults, post-sign background presign traffic is expected.

## 6. Log Labeling for Background Refill

Background refill requests now carry `requestTag: "background_presign_pool_refill"` from client refill code, and server request logs map that to:

- `label: "background presign pool refill"`

So when you see that label on `/threshold-ecdsa/presign/init` or `/threshold-ecdsa/presign/step`, it is refill traffic, not the foreground sign operation.

## 7. Presignature Lifecycle and Single-Use Rules

```mermaid
stateDiagram-v2
    [*] --> Generating
    Generating --> Available: presign_done
    Available --> Reserved: sign/init reserves by id
    Reserved --> Consumed: sign/finalize succeeds
    Reserved --> Discarded: timeout / abort / cleanup
    Available --> Expired: TTL expiry
    Expired --> [*]
    Consumed --> [*]
    Discarded --> [*]
```

Required invariants:

1. Presignatures are one-time use.
2. A reserved presignature must be consumed or discarded; never returned to available state without strict protocol support.
3. Reuse of nonce-related presign material across messages is unsafe.

## 8. Security and Secret-Handling Notes

### 8.1 Highly sensitive (must stay private)

Do not log or expose:

1. `clientSigningShare32`
2. Presign private shares: `kShareB64u`, `sigmaShareB64u`
3. WebAuthn PRF output (`prfFirstB64u`)
4. Threshold session JWT/cookie secrets

Treat these like key material.

### 8.2 Sensitive but lower impact (still minimize logging)

1. `presignatureId`
2. `bigRB64u`

These are less sensitive than secret shares but can still aid correlation and traffic analysis.

### 8.3 Public output

1. Final ECDSA signature (`signature65`) is public by nature once broadcast.

### 8.4 Storage guidance

1. Client presign shares are intentionally memory-only by default (lower at-rest risk).
2. If persisting client presign shares in IndexedDB, require strong local encryption, strict TTL, single-use delete semantics, and crash-safe consume flow.
3. Server-side presign pool must enforce reservation and consume atomically.

### 8.5 Randomness requirements

1. Every presign session must use fresh randomness.
2. Never deterministically reuse presign nonce material across signatures.
3. Randomness quality directly affects ECDSA security.

## 9. Operational Footguns

1. Two independent client runtimes (for example, two tabs/hosts) can each run refill for the same account and increase duplicate background work.
2. In-memory server stores are unsafe for multi-instance deployments (state split and `pool_empty`/session mismatch behavior).
3. Mixed backend/prefix config across instances creates split-brain pool state.
4. High refill targets can consume substantial CPU because each presignature needs a full handshake.

## 10. Practical Tuning Suggestions

For better interactive latency:

1. Keep `maxRefillInFlight` low (often `1`).
2. Start with modest pool depth (`targetDepth` around `1-3`) unless throughput requires more.
3. Keep refill background and non-blocking for UX.
4. Track separate metrics for foreground sign latency vs refill latency.

## 11. Relevant Code Paths

Client:

1. Presign pool + handshake + refill scheduler:
   - `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
2. ECDSA signing flow, authorize, and refill triggers:
   - `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`
3. HTTP request wrappers for `/threshold-ecdsa/presign/*`:
   - `client/src/core/signingEngine/threshold/workflows/signEcdsa.ts`

Server:

1. ECDSA presign/sign handlers:
   - `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
2. Express route logging (`durationMs`, request metadata):
   - `server/src/router/express/routes/thresholdEcdsa.ts`

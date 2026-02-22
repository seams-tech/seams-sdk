# Threshold ECDSA Presigning Pool

Last updated: 2026-02-22

## 1. Overview

Threshold ECDSA presigning uses two coordinated pools:

1. Client presign pool (browser memory): holds the client share of presignature material.
2. Server presign pool (persistent backend): holds the relayer share of presignature material.

This split is intentional. The protocol is 2-party; both sides must hold their own material and agree on the same `presignatureId` for a sign.

## 2. How It Works

1. Presign generation:
- Client and server run the presign handshake (`/threshold-ecdsa/presign/init`, `/threshold-ecdsa/presign/step`).
- On `presign_done`, both sides derive the same `bigR`.
- Server stores its presign record in the server pool (`put`).
- Client can cache its presign record in its in-memory pool.

2. Sign initialization:
- Client sign path tries to pop one presign record from its local pool.
- Client calls `/threshold-ecdsa/sign/init` and includes `clientRound1.presignatureId`.
- Server reserves that exact presignature (`reserveById`) when available, otherwise returns `pool_empty`.

3. Sign finalize:
- Server consumes the reserved presignature (`consume`) exactly once.
- If the flow fails or expires before finalize, server discards the reservation (`discard`).

4. Refill / rebalance:
- Refill is client-driven and best-effort.
- Scheduler runs when:
  - commit starts and depth is at/below low watermark,
  - post-sign success to top up toward target depth.
- Scheduler dedupes per pool key and enforces global in-flight limits.
- Refill loops until `targetDepth` or `refillAttemptTimeoutMs`.

## 3. Pool Keying Model

## 3.1 Client Pool Key

Client presign pool entries are keyed by:

- `relayerUrl`
- `relayerKeyId`
- `clientVerifyingShareB64u`
- `participantIds`

This isolates pool entries per relayer endpoint and session identity tuple.

## 3.2 Server Pool Key

Server presign pool entries are keyed by:

- `namespace` (prefix/config scope)
- `relayer_key_id`
- `presignature_id`

Important identity note:
- The server pool is keyed directly by `relayerKeyId`, not `userId`.
- `relayerKeyId` is cryptographically bound during authorize to:
  - `userId`
  - `rpId`
  - `clientVerifyingShareB64u`
- So user scope is enforced indirectly via `relayerKeyId` binding.

## 4. Where Pools Are Stored

## 4.1 Client Pool Storage

- In-memory `Map` in the wallet-origin coordinator module.
- Process-local only (cleared on refresh/tab close/new worker lifetime).
- Not shared across tabs/devices/processes.

## 4.2 Server Pool Storage

Backend is selected by threshold store config:

1. Cloudflare Durable Objects:
- Available list key: `...avail:{relayerKeyId}`
- Reserved key prefix: `...res:{relayerKeyId}:{presignatureId}`

2. Upstash Redis REST:
- Available list in Redis list (`RPUSH` / reserve via Lua `LPOP` flow).
- Reserved entries as separate keys with TTL.

3. Redis TCP:
- Same model as Upstash (Lua reserve/reserveById + reserved key TTL).

4. Postgres:
- Table: `threshold_ecdsa_presignatures`
- Columns include `namespace`, `relayer_key_id`, `presignature_id`, `state`, `reserve_expires_at_ms`.
- Reservation uses `FOR UPDATE SKIP LOCKED` and state transition `available -> reserved`.

5. In-memory:
- Dev fallback only, process-local, not shared across server instances.

## 5. Rebalance Policy

Current default client policy:

- `enabled: true`
- `targetDepth: 20`
- `lowWatermark: 5`
- `maxRefillInFlight: 2`
- `refillAttemptTimeoutMs: 30000`

Policy source:

1. Client default config.
2. Optional server hint in `/threshold-ecdsa/authorize` response.
3. Client clamps final values to local safety bounds.

## 6. Multi-Instance Footguns

## 6.1 In-Memory Stores Across Multiple Servers

Problem:
- Each instance has its own isolated pool/session state.
- A request can authorize on instance A but sign on instance B and fail with missing/expired session or `pool_empty`.

Mitigation:
- Use shared persistent backends (DO, Upstash/Redis, Postgres) for server presign pool and sessions.
- Avoid in-memory store mode in load-balanced deployments.

## 6.2 Mixed Store Configuration Across Instances

Problem:
- Some instances use Redis, others Postgres/in-memory.
- State becomes split-brain and non-deterministic.

Mitigation:
- Ensure every instance in the fleet uses the same store kind and credentials.

## 6.3 Prefix / Namespace Drift

Problem:
- Different `THRESHOLD_PREFIX` or ECDSA-specific prefixes across instances.
- Instances write/read different logical pools.

Mitigation:
- Standardize prefix env vars across all instances.

## 6.4 Durable Object Binding Mismatch

Problem:
- Instances point to different DO namespaces/object names.
- Same split-brain behavior as prefix drift.

Mitigation:
- Keep identical DO binding config for all instances.

## 6.5 Time Skew and Reservation TTL

Problem:
- Reservation expiry checks are time-based.
- Severe clock skew can increase false expiry behavior.

Mitigation:
- Keep server clocks synchronized (NTP).
- Use sane reservation TTL values.

## 6.6 Throughput vs Target Depth

Problem:
- High `targetDepth` with many active users can generate heavy presign churn.
- `count=1` presign endpoint means refills are looped, not batched.

Mitigation:
- Start with conservative policy (current `20/5`).
- Tune based on observed presign latency and backend load.

## 7. Operational Checklist

Before multi-instance rollout:

1. Use one shared persistent store backend for all instances.
2. Confirm identical threshold env/prefix settings everywhere.
3. Confirm presign pool hint settings are consistent (or unset) fleet-wide.
4. Verify sign path under concurrency with at least two app instances behind LB.
5. Monitor:
- `pool_empty` rates
- sign timeout rates
- reserve/consume failures
- refill scheduling reasons (`in_flight_for_pool_key`, `global_in_flight_limit`, etc.)


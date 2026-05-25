# Ed25519 Presign Pool and One-RTT Dispatch Plan

Date updated: May 24, 2026

## Goal

Make warm Ed25519 threshold transaction signing use one visible client-server
round trip by default.

The default warm path should be:

1. keep a small pool of single-use FROST presign entries ready after
   login/unlock/session warmup
2. when the user signs, consume one ready presign entry locally
3. send one request containing the transaction, `presignId`, and client
   signature share
4. have the server consume the matching relayer presign entry, aggregate the
   signature, and dispatch the transaction

The fallback path should be:

1. when the presign pool is depleted, expired, or still refilling, use the
   existing two-RTT `/threshold-ed25519/sign/init` +
   `/threshold-ed25519/sign/finalize` path for that sign
2. refill the presign pool in the background so the next sign returns to the
   one-RTT path

There should be no config flag to pick between paths. The SDK chooses the
presign path whenever a ready entry exists, and the two-RTT path is the
intentional depleted-pool fallback.

## Resolved Decisions

- **Default path:** one-RTT Ed25519 presign finalize-and-dispatch.
- **Fallback path:** existing two-RTT Ed25519 signing when the client has no
  ready presign entry.
- **Presign authority:** threshold-session auth, not digest-scoped
  `mpcSessionId`.
- **Budget consume point:** final one-RTT sign route, because it is the first
  digest-specific operation in the presign path.
- **Presign refill:** SDK-triggered after login/unlock/session warmup and after
  successful signing.
- **Nonce ownership:** client nonce secrets remain client-worker-local; relayer
  nonce secrets remain server-side.
- **Server dispatch:** NEAR transaction signing uses finalize-and-dispatch by
  default. Signature-only finalize remains available for non-transaction flows
  such as NEP-413 and delegate signing.
- **Route cleanup:** keep `/threshold-ed25519/sign/init` and
  `/threshold-ed25519/sign/finalize` as the depleted-pool fallback. Remove only
  temporary migration shims, duplicate helper code, and experimental branches.

## Current Flow

Current warm Ed25519 threshold signing does FROST round 1 and round 2 in the
visible signing path:

```text
Client:
  create FROST round-1 nonces + commitments

RTT 1: POST /threshold-ed25519/sign/init
  client -> server:
    mpcSessionId
    relayerKeyId
    nearAccountId
    signingDigestB64u
    clientCommitments

  server:
    validates digest-scoped mpcSessionId
    creates relayer nonces + commitments
    stores signingSessionId with transcript

  server -> client:
    signingSessionId
    relayer commitments
    relayer verifying share

Client:
  compute client signature share

RTT 2: POST /threshold-ed25519/sign/finalize
  client -> server:
    signingSessionId
    clientSignatureShareB64u

  server:
    computes relayer signature share

  server -> client:
    relayer signature share

Client:
  aggregate final Ed25519 signature
```

## Target Flow

The target path moves FROST round 1 to a background presign refill.

```text
Background refill:
  client creates one-time FROST nonces + commitments
  client sends commitments to server
  server creates relayer nonces + commitments
  server stores relayer nonces under presignId
  client stores local nonce handle + transcript under clientPresignId/presignId

User signing:
  client builds unsigned NEAR transaction
  client computes signing digest
  client reserves a ready presign entry
  client computes client signature share

RTT 1: POST /threshold-ed25519/sign/finalize-and-dispatch
  client -> server:
    threshold-session auth
    presignId
    relayerKeyId
    nearAccountId
    unsigned transaction bytes or digest-only request
    client signature share

  server:
    validates auth and budget
    recomputes digest from unsigned transaction bytes when dispatching
    atomically consumes presignId
    computes relayer signature share
    aggregates final Ed25519 signature
    verifies final signature
    dispatches transaction or returns signature-only result

  server -> client:
    dispatch result or final signature
```

The final signature is still message-dependent. The presign pool stores only the
message-independent nonce/commitment transcript.

## Compatibility

This fits the existing implementation because `/threshold-ed25519/sign/init`
already does the same work the presign refill route needs:

- client creates FROST round-1 commitments
- server creates relayer FROST round-1 commitments
- server stores relayer nonces in short-lived state
- client computes the signature share after it has both commitments
- server computes the relayer signature share from stored relayer nonces

The new implementation should refactor shared logic rather than duplicate it:

- current `/sign/init` and new `/presign/refill` both call one relayer presign
  creation helper
- current `/sign/finalize` and new `/sign/finalize-and-dispatch` both call one
  relayer signature-share helper
- new finalize-and-dispatch adds server-side aggregation plus either NEAR
  dispatch or signature-only return
- current two-RTT path remains available for depleted-pool signing

## Route Contracts

### Auth Rules

`/threshold-ed25519/presign/refill`:

- route class: threshold-session route
- auth: existing threshold-session JWT bearer or cookie auth
- budget: does not consume a signing use
- purpose: prepare message-independent nonce transcripts

`/threshold-ed25519/sign/finalize-and-dispatch`:

- route class: threshold-session route
- auth: existing threshold-session JWT bearer or cookie auth
- budget: consumes one signing use after request validation and before returning
  a final signature or dispatching
- purpose: complete one message-dependent signature from one presign

`/threshold-ed25519/sign/init` and `/threshold-ed25519/sign/finalize`:

- route class: public threshold protocol continuation, as today
- authority: digest-scoped `mpcSessionId` plus protocol-state possession
- purpose: depleted-pool fallback path

### `POST /threshold-ed25519/presign/refill`

Request body:

```ts
type ThresholdEd25519PresignRefillRequest = {
  kind: 'threshold_ed25519_presign_refill_v1';
  relayerKeyId: string;
  nearAccountId: string;
  participantIds: readonly number[];
  clientPresigns: readonly ThresholdEd25519ClientPresignOffer[];
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
};

type ThresholdEd25519ClientPresignOffer = {
  clientPresignId: string;
  clientCommitments: ThresholdEd25519Commitments;
};

type ThresholdEd25519Commitments = {
  hiding: string;
  binding: string;
};
```

Response body:

```ts
type ThresholdEd25519PresignRefillResponse =
  | {
      ok: true;
      kind: 'threshold_ed25519_presign_refill_response_v1';
      accepted: readonly ThresholdEd25519PresignPair[];
      rejectedClientPresignIds: readonly string[];
      serverTimeMs: number;
    }
  | {
      ok: false;
      code: ThresholdEd25519PresignRefillErrorCode;
      message: string;
    };

type ThresholdEd25519PresignPair = {
  presignId: string;
  clientPresignId: string;
  relayerCommitments: ThresholdEd25519Commitments;
  relayerVerifyingShareB64u: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

type ThresholdEd25519PresignRefillErrorCode =
  | 'invalid_body'
  | 'unauthorized'
  | 'forbidden'
  | 'expired'
  | 'wrong_scope'
  | 'invalid_commitments'
  | 'capacity_exceeded'
  | 'internal';
```

Server behavior:

- parse and normalize the request at the route boundary
- validate threshold-session auth
- verify `nearAccountId`, `relayerKeyId`, participant ids, wallet signing
  session, RP/runtime scope, and active key scope
- cap accepted count, initially `1..8`
- for each accepted client offer:
  - create relayer nonces and commitments with the existing
    `threshold_ed25519_round1_commit` path
  - generate an unguessable server `presignId`
  - persist relayer nonces and transcript under `presignId`
- return the accepted mapping from `clientPresignId` to `presignId`

Client behavior:

- create client nonces and commitments in the near signer worker
- keep nonce secrets behind worker-local handles
- send only commitments to the server
- mark accepted entries as ready after receiving relayer commitments
- discard and zeroize rejected offers

### `POST /threshold-ed25519/sign/finalize-and-dispatch`

Request body:

```ts
type ThresholdEd25519FinalizeAndDispatchRequest =
  | ThresholdEd25519FinalizeSignatureOnlyRequest
  | ThresholdEd25519FinalizeAndDispatchNearTxRequest;

type ThresholdEd25519FinalizeSignatureOnlyRequest = {
  kind: 'threshold_ed25519_finalize_signature_only_v1';
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  signingDigestB64u: string;
  clientSignatureShareB64u: string;
};

type ThresholdEd25519FinalizeAndDispatchNearTxRequest = {
  kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1';
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
  clientSignatureShareB64u: string;
  dispatch: {
    kind: 'near_rpc_configured_default_v1';
  };
};
```

Response body:

```ts
type ThresholdEd25519FinalizeAndDispatchResponse =
  | {
      ok: true;
      kind: 'threshold_ed25519_signature_only_result_v1';
      signatureB64u: string;
      signerPublicKey: string;
    }
  | {
      ok: true;
      kind: 'threshold_ed25519_dispatched_near_tx_result_v1';
      signatureB64u: string;
      signerPublicKey: string;
      signedTransactionBorshB64u: string;
      transactionHash: string;
      rpcResult: unknown;
    }
  | {
      ok: false;
      code: ThresholdEd25519FinalizeAndDispatchErrorCode;
      message: string;
      presignConsumed: boolean;
      dispatchState: 'not_attempted' | 'attempted' | 'unknown';
    };

type ThresholdEd25519FinalizeAndDispatchErrorCode =
  | 'invalid_body'
  | 'unauthorized'
  | 'forbidden'
  | 'expired'
  | 'wrong_scope'
  | 'presign_unavailable'
  | 'presign_expired'
  | 'presign_consumed'
  | 'digest_mismatch'
  | 'invalid_signature_share'
  | 'signature_verification_failed'
  | 'dispatch_failed'
  | 'internal';
```

Server behavior:

- validate threshold-session auth and signing budget
- validate account, relayer key, participant ids, session scope, and runtime
  scope against the presign record
- for NEAR dispatch mode, recompute the canonical signing digest from
  `unsignedTransactionBorshB64u` and compare it to `signingDigestB64u`
- atomically consume `presignId`
- compute relayer signature share from stored relayer nonces and stored
  commitments
- aggregate the client and relayer shares into a final Ed25519 signature
- verify the final signature against the stored group public key and digest
- for dispatch mode, encode the signed transaction and submit it through the
  configured server NEAR RPC target
- return the final signature plus dispatch result

Client behavior:

- reserve a ready local presign entry before computing a client signature share
- build the signing package from stored client commitments, relayer commitments,
  participant ids, and digest
- compute `clientSignatureShareB64u`
- send one finalize-and-dispatch request
- zeroize and permanently burn the local presign entry once the request is sent

## State Model

Use explicit lifecycle states. Core logic should not accept optional protocol
fields or raw external shapes.

### Client Presign Pool

```ts
type Ed25519ClientPresignEntry =
  | {
      state: 'offered';
      clientPresignId: string;
      nonceHandle: Ed25519ClientPresignNonceHandle;
      clientCommitments: ThresholdEd25519Commitments;
      createdAtMs: number;
    }
  | {
      state: 'ready';
      presignId: string;
      clientPresignId: string;
      nonceHandle: Ed25519ClientPresignNonceHandle;
      clientCommitments: ThresholdEd25519Commitments;
      relayerCommitments: ThresholdEd25519Commitments;
      relayerVerifyingShareB64u: string;
      participantIds: readonly number[];
      expiresAtMs: number;
    }
  | {
      state: 'burned';
      presignId: string;
      reason: 'used' | 'expired' | 'rejected' | 'stale_generation' | 'send_attempted';
      burnedAtMs: number;
    };

type Ed25519ClientPresignPoolState =
  | {
      state: 'disabled';
      reason: 'no_threshold_session' | 'unsupported_signer' | 'worker_unavailable';
    }
  | {
      state: 'ready';
      scopeKey: string;
      generation: number;
      targetDepth: number;
      lowWatermark: number;
      entries: readonly Ed25519ClientPresignEntry[];
      refill: Ed25519PresignRefillState;
    };

type Ed25519PresignRefillState =
  | { state: 'idle' }
  | { state: 'in_flight'; startedAtMs: number; requestTag: string }
  | { state: 'failed'; failedAtMs: number; code: string; message: string };
```

The TypeScript pool tracks lifecycle and worker handles. The actual client nonce
secrets stay inside the near signer worker.

### Server Presign Record

```ts
type ThresholdEd25519PresignRecord = {
  kind: 'threshold_ed25519_presign_record_v1';
  expiresAtMs: number;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  rpId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope | null;
  participantIds: readonly number[];
  groupPublicKey: string;
  clientCommitments: ThresholdEd25519Commitments;
  relayerCommitments: ThresholdEd25519Commitments;
  relayerVerifyingShareB64u: string;
  relayerNoncesB64u: string;
};
```

Storage rules:

- `putPresign(id, record, ttlMs)` stores one presign record
- `takePresign(id)` is atomic get-and-delete
- TTL default is 120 seconds
- expired entries are unusable and may be garbage-collected lazily
- duplicate consume returns `presign_unavailable` or `presign_consumed`
- logs may include `presignId` prefixes or hashes, never nonce material or
  signature shares

## Fallback Policy

Fallback is chosen before a client signature share for a presign is sent.

```text
if ready presign entry exists:
  use one-RTT finalize-and-dispatch
  schedule background refill after success
else:
  schedule foreground/background refill if no refill is in flight
  use current two-RTT sign/init + sign/finalize path for this sign
```

Automatic fallback after sending a presigned client signature share is limited:

- if the HTTP request is never sent, the SDK may burn the local presign and use
  the two-RTT path
- if the request was sent and the response is ambiguous, the SDK must surface an
  ambiguous signing result and avoid automatic re-dispatch
- if the server explicitly returns `presign_unavailable` before consume with
  `dispatchState: 'not_attempted'`, the SDK may retry with a fresh two-RTT
  signature only when the caller's signing operation idempotency policy permits
  it

This avoids accidental duplicate transaction dispatch after network failures.

## Security Invariants

- FROST nonces are single-use.
- A presign entry binds one account, one threshold session, one wallet signing
  session, one relayer key, one participant set, one RP/runtime scope, and one
  public key.
- `presignId` is unguessable and server-generated.
- Client nonce secrets never leave the near signer worker.
- Server nonce secrets never leave the server-side signing service.
- Finalize burns server presign state atomically before relayer share output can
  be reused.
- The client burns local nonce state once a presigned finalize request is sent.
- Dispatch mode recomputes the NEAR signing digest from unsigned transaction
  bytes.
- The server verifies the final Ed25519 signature before returning or
  dispatching.
- Metrics and logs never include nonce secrets, signing shares, raw client share
  material, or full signed transaction bytes.
- New scalar/signature math stays in Rust/FROST helpers. TypeScript handles
  protocol state, route calls, and byte transport.

## Files To Change

### Rust Core And WASM

- `crates/signer-core/src/near_threshold_ed25519.rs`
  - expose `aggregate_signature` and signature verification through the
    higher-level `near_threshold_frost` finalize helper
- `crates/signer-core/src/near_threshold_frost.rs`
  - add `threshold_ed25519_finalize_signature` or equivalent helper that accepts
    participant ids, public key, commitments, client share, relayer share, and
    digest, then returns the final signature
  - keep existing `threshold_ed25519_round1_commit` and
    `threshold_ed25519_round2_sign` as shared helpers
- `wasm/near_signer/src/threshold/threshold_frost.rs`
  - export the new server-side aggregate/finalize helper
- `wasm/near_signer/src/threshold/protocol.rs`
  - add reusable client-side presign helpers around existing FROST functions
- `wasm/near_signer/src/threshold/coordinator.rs`
  - add one-RTT presign signing path beside `sign_ed25519_2p_v1`
  - keep `sign_ed25519_2p_v1` as depleted-pool fallback
- `wasm/near_signer/src/threshold/transport.rs`
  - add transport methods for presign refill and finalize-and-dispatch
- `wasm/near_signer/src/threshold/relayer_http.rs`
  - implement HTTP calls to `/threshold-ed25519/presign/refill` and
    `/threshold-ed25519/sign/finalize-and-dispatch`
- `wasm/near_signer/src/threshold/presign_pool.rs`
  - new worker-local client nonce handle store
  - owns create, mark-ready, reserve, burn, cleanup operations
- `wasm/near_signer/src/types/worker_messages.rs`
  - add `PrepareThresholdEd25519PresignPool`
  - add `GetThresholdEd25519PresignPoolStatus`
  - add `ClearThresholdEd25519PresignPool`
  - add matching success/failure response variants
- `wasm/near_signer/src/lib.rs`
  - dispatch the three new worker messages
- `wasm/near_signer/pkg*`
  - regenerated outputs after the Rust/WASM changes

### Server

- `server/src/core/types.ts`
  - add request/response types for refill and finalize-and-dispatch
  - add error-code unions
- `server/src/core/ThresholdService/stores/SessionStore.ts`
  - add `ThresholdEd25519PresignRecord`
  - add `putPresign` and `takePresign`
  - implement the presign methods for the existing Ed25519 in-memory,
    Redis/Upstash REST, Postgres, and Cloudflare Durable Object store variants
- `server/src/core/ThresholdService/validation.ts`
  - parse and validate presign records and route requests
- `server/src/core/ThresholdService/postgresRecords.ts`
  - add current-shape parser for persisted presign records in the shared
    Ed25519 session table
- `server/src/core/ThresholdService/signingHandlers.ts`
  - add `thresholdEd25519PresignRefill`
  - add `thresholdEd25519FinalizeAndDispatch`
  - refactor existing sign init/finalize to share presign creation and relayer
    share computation helpers
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - wire new handlers into the threshold Ed25519 scheme object
- `server/src/core/ThresholdService/createThresholdSigningService.ts`
  - use the extended Ed25519 session store with presign methods
- `server/src/router/routeDefinitions.ts`
  - add route definitions and route-auth metadata
- `server/src/router/express/routes/thresholdEd25519.ts`
  - add Express routes
- `server/src/router/cloudflare/routes/thresholdEd25519.ts`
  - add Cloudflare routes
- `server/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - add atomic `takePresign` support for Durable Object-backed Ed25519 session
    storage

### Client TypeScript

- `client/src/core/types/signer-worker.ts`
  - add Ed25519 presign pool policy fields to `ThresholdSignerConfig`
  - add worker payload/result shapes for:
    - `PrepareThresholdEd25519PresignPool`
    - `GetThresholdEd25519PresignPoolStatus`
    - `ClearThresholdEd25519PresignPool`
- `client/src/core/signingEngine/threshold/ed25519/presignPool.ts`
  - new TypeScript lifecycle owner for pool depth, generation, refill
    scheduling, and fallback decisions
  - calls the near signer worker to refill/status/clear the Rust-owned pool
  - does not store nonce secrets
- `client/src/core/signingEngine/flows/signNear/signTransactions.ts`
  - schedule presign refill after warm session readiness
  - choose one-RTT path on pool hit
  - choose two-RTT fallback on pool miss
  - map dispatch results into existing `SignTransactionResult[]`
- `client/src/core/signingEngine/flows/signNear/signDelegate.ts`
  - use signature-only one-RTT path on pool hit and two-RTT fallback on pool
    miss
- `client/src/core/signingEngine/flows/signNear/signNep413.ts`
  - use signature-only one-RTT path on pool hit and two-RTT fallback on pool
    miss
- `client/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
  - trigger initial refill after session mint/provision
- `client/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts`
  - trigger refill for Email OTP warm sessions
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
  - add operation types for prepare/status/clear presign pool messages
- `client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
  - no protocol logic; pass through the three new worker messages
- `client/src/core/config/defaultConfigs.ts`
  - add Ed25519 presign pool defaults

### Tests And Docs

- `tests/relayer/threshold-ed25519.scope.test.ts`
  - route contract and misuse tests
- `tests/unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts`
  - active signing path tests with pool hit, pool miss, stale presign, and
    fallback
- `tests/unit/thresholdEd25519.presignPool.unit.test.ts`
  - new pool lifecycle/type tests
- `tests/unit/signingEngine.*.guard.unit.test.ts`
  - type/static guard updates for new domain state
- `docs/auth-gating-routes.md`
  - route auth classification update
- `docs/load-testing.md`
  - add Ed25519 presign pool scenarios
- `docs/benchmarks/threshold-load.md`
  - record before/after route counts and latency

## Implementation Phases

### Phase 0: Baseline And Static Contracts

- Capture current warm Ed25519 signing route count and latency.
- Add request/response/domain type sketches in `server/src/core/types.ts` and
  client type fixtures.
- Add static tests that reject invalid presign lifecycle branches.

Validation:

- targeted typecheck for touched TS files
- current threshold Ed25519 active-path test

### Phase 1: Core FROST Helpers

- Add the server-side finalize/aggregate helper in Rust.
- Add tests proving:
  - presign commitments plus later digest produce the same final signature shape
    as the current two-RTT flow
  - mismatched digest fails verification
  - mismatched commitments fail aggregation or verification
- Run constant-time review on new Rust helpers; all scalar/signature operations
  should remain inside FROST/curve libraries.

Validation:

- `cargo test -p signer-core near_threshold`
- near signer wasm build

### Phase 2: Server Presign Store

- Add `ThresholdEd25519PresignRecord`.
- Add `putPresign` and atomic `takePresign`.
- Implement storage variants used by local tests and Cloudflare/serverless
  deployments.
- Add race tests for double consume.

Validation:

- store unit tests
- route tests still pass with existing signing path

### Phase 3: Presign Refill Route

- Add route definitions and Express/Cloudflare handlers.
- Add service method that validates threshold-session auth, creates relayer
  commitments, stores presigns, and returns accepted pairs.
- Add client/worker refill call that produces client offers and marks accepted
  entries ready.

Validation:

- refill success test
- wrong account/session/relayer/participant tests
- malformed commitments test
- no budget decrement on refill

### Phase 4: Client Presign Pool

- Implement pool depth policy:
  - default `targetDepth = 2`
  - default `lowWatermark = 1`
  - max accepted refill count `8`
  - entry TTL follows server expiry
- Implement generation invalidation on:
  - threshold session change
  - wallet signing session change
  - relayer key change
  - participant id change
  - client base/share change
- Implement fallback selector:
  - pool hit -> one-RTT
  - pool miss -> schedule refill and use two-RTT

Validation:

- pool lifecycle unit tests
- stale generation tests
- concurrent refill suppression tests
- local nonce burn/zeroization tests

### Phase 5: Finalize-And-Dispatch Route

- Add route definitions and Express/Cloudflare handlers.
- Add service method that consumes presign, computes relayer share, aggregates,
  verifies, and dispatches.
- Add digest recomputation from unsigned NEAR transaction bytes.
- Add signature-only branch for non-dispatch signing flows.

Validation:

- signature-only route success
- dispatch route success
- digest mismatch rejects
- wrong scope rejects
- replay/double consume rejects
- ambiguous dispatch state is represented in the response

### Phase 6: Switch Default Signing Behavior

- Update warm Ed25519 transaction signing:
  - attempt one-RTT finalize-and-dispatch when a ready presign entry exists
  - fallback to current two-RTT sign path when the pool is depleted/refilling
  - schedule refill after success or pool miss
- Preserve existing result shapes expected by `signTransactionsWithActions`.
- Add metrics:
  - `ed25519_presign_pool_hit`
  - `ed25519_presign_pool_miss`
  - `ed25519_presign_refill_in_flight`
  - `ed25519_one_rtt_finalize_ms`
  - `ed25519_two_rtt_fallback_ms`

Validation:

- active-path tests
- warm-session login/unlock tests
- Email OTP warm-session tests
- transaction signing tests with pool hit and pool miss

### Phase 7: Cleanup And Hardening

- Remove temporary duplicate helper paths introduced during implementation.
- Keep the two-RTT routes as the depleted-pool fallback.
- Share helper code between presign refill and two-RTT sign init.
- Share helper code between finalize-and-dispatch and two-RTT sign finalize.
- Update docs and benchmark tables.
- Add load tests for concurrent consumes and refill pressure.

Validation:

- `pnpm -C tests test:threshold-ed25519:active-path`
- targeted route/unit tests
- load-test scenario for pool hit/miss/refill

## Benchmark Plan

Measure these scenarios before and after:

- current warm sign with `/sign/init` + `/sign/finalize`
- warm sign with presign pool hit and server dispatch
- warm sign with presign pool hit and signature-only finalize
- warm sign with empty pool and two-RTT fallback
- concurrent sign attempts with one ready presign
- expired presign cleanup
- cross-worker/serverless double-consume race

Metrics:

- visible client signing latency
- route count per sign
- presign refill latency
- finalize-and-dispatch latency
- pool hit ratio
- pool miss fallback latency
- presign consume replay failures
- dispatch success/failure latency

Expected result:

- warm pool-hit transaction signing drops from two visible MPC RTTs to one
  visible RTT
- cold or depleted-pool signing remains close to current latency for that sign
- refill makes subsequent signs return to the one-RTT path

## Todo

- [ ] Add static request/response and lifecycle type fixtures.
- [ ] Add Rust server-side Ed25519 aggregate/finalize helper.
- [ ] Add server presign record and atomic store methods.
- [ ] Add `/threshold-ed25519/presign/refill`.
- [ ] Add worker-local client nonce handle pool.
- [ ] Add TypeScript Ed25519 presign pool lifecycle module.
- [ ] Add `/threshold-ed25519/sign/finalize-and-dispatch`.
- [ ] Switch transaction signing default to one-RTT pool-hit path.
- [ ] Keep two-RTT signing as depleted-pool fallback.
- [ ] Add pool hit/miss/refill metrics.
- [ ] Add benchmarks and load tests.
- [ ] Update route auth and SDK docs.

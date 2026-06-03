# Ed25519 Presign Pool and One-RTT Dispatch Plan

Date updated: June 3, 2026

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
- **Budget idempotency:** finalize consumes budget exactly once per canonical
  signing operation. The consume key is derived from the operation id,
  operation fingerprint, wallet signing session, and digest.
- **Presign refill:** SDK-triggered after login/unlock/session warmup and after
  successful signing.
- **Nonce ownership:** client nonce secrets remain client-worker-local; relayer
  nonce secrets remain server-side.
- **Client presign durability:** presigns are in-memory worker state only. A
  page reload, worker restart, logout, account switch, threshold-session change,
  or wallet-signing-session change burns local entries and leaves any matching
  server entries to TTL cleanup.
- **Server dispatch:** NEAR transaction signing uses finalize-and-dispatch by
  default after the server parses and validates the unsigned transaction against
  the authenticated session, expected signer account, expected access key,
  network/RPC policy, relayer key, digest, and presign scope. Signature-only
  finalize remains available for non-transaction flows such as NEP-413 and
  delegate signing.
- **Contract ownership:** new request, response, record, and worker-message
  shapes must use the existing boundary-parser/generated-schema pattern. Manual
  TypeScript sketches in this plan are contract intent, not implementation
  shortcuts.
- **Route cleanup:** keep `/threshold-ed25519/sign/init` and
  `/threshold-ed25519/sign/finalize` as the depleted-pool fallback. Remove only
  temporary migration shims, duplicate helper code, and experimental branches.

## Implementation Readiness Review

No additional product or protocol input is required before implementation. The
remaining decisions are repo-owned engineering choices and are resolved here.

- **Auth boundary:** new `/threshold-ed25519/presign/refill` and
  `/threshold-ed25519/sign/finalize-and-dispatch` routes use the existing
  `validateThresholdEd25519SessionTokenInputs` boundary. Parsed
  `ThresholdEd25519SessionClaims` are the source of truth for
  `sessionId`, `walletSigningSessionId`, `walletId`, `rpId`, `relayerKeyId`,
  `participantIds`, `runtimePolicyScope`, and `thresholdExpiresAtMs`. Route
  body scope fields are request assertions that must match the claims and
  stored presign record.
- **Auth-plane split:** add the new presign routes as `thresholdSessionRoute`
  entries in `server/src/router/routeDefinitions.ts`. Keep
  `/threshold-ed25519/sign/init`, `/threshold-ed25519/sign/finalize`, and the
  internal cosign continuation routes as public protocol-state routes.
- **Service ownership:** the Express and Cloudflare route handlers parse session
  auth once, then pass parsed claims plus a parsed route body into the threshold
  Ed25519 service method. Low-level helpers in `signingHandlers.ts` should own
  FROST transcript creation, relayer share computation, presign storage, and
  shared local/cosigner fanout mechanics. Budget consume and session-claim
  policy checks stay in the auth-aware service layer or an injected
  auth-aware presign handler.
- **Operation identity:** callers do not need to supply new input beyond the
  existing signing operation id surface. Transaction signing already computes
  `operationFingerprint` with `computeSigningOperationFingerprint` and binds
  caller-provided operation ids through `SigningOperationIdBindingRegistry`.
  Delegate and NEP-413 flows must add equivalent canonical fingerprints before
  choosing one-RTT presign or two-RTT fallback.
- **Budget idempotency:** finalize-and-dispatch uses the existing
  `consumeUseCountOnce` path through `consumeWalletOrCurveSessionUse`. Its
  idempotency key is derived from
  `(operationId, operationFingerprint, walletSigningSessionId,
  signingDigestB64u)`. A missing operation fingerprint is an invalid request
  for the presign path.
- **Presign storage:** extend `ThresholdEd25519SessionStore` with a distinct
  presign record kind and parser. In-memory, Redis/Upstash, Postgres, and
  Cloudflare Durable Object stores must expose the same `putPresign` and
  atomic `takePresignForFinalize` behavior. The store validates current-shape
  records at write/read boundaries and deletes malformed persisted rows.
- **Dispatch scope:** transaction finalize-and-dispatch uses the configured
  server NEAR RPC policy from the authenticated runtime scope. The request can
  assert `dispatch.kind: 'near_rpc_configured_default_v1'`; it cannot choose an
  arbitrary RPC URL.
- **Client pool policy:** Ed25519 uses a default-on pool with fixed defaults
  (`targetDepth = 2`, `lowWatermark = 1`, `max accepted refill count = 8`).
  There is no SDK-facing enable/disable flag. A missing, stale, expired, or
  refilling pool selects the existing two-RTT fallback.
- **Math boundary:** all new scalar, share, aggregate, and final-signature
  verification work stays in Rust/WASM helpers. TypeScript owns lifecycle,
  boundary parsing, route calls, durable records, and error-state modeling.
- **Implementation order:** Phase 0 must land parsers, domain types, static
  fixtures, route definitions, and service method signatures before Rust/WASM
  or route behavior changes. This prevents raw strings and optional protocol
  bags from leaking into core logic.

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
    operation id and canonical operation fingerprint
    presignId
    relayerKeyId
    nearAccountId
    nearNetworkId
    expected signer public key
    unsigned transaction bytes or digest-only request
    client signature share

  server:
    validates auth and budget availability
    validates the operation fingerprint
    parses unsigned transaction bytes when dispatching
    validates signer account, access key, network/RPC policy, and digest
    atomically consumes presignId
    consumes budget exactly once
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

The TypeScript shapes below describe the intended wire contract. Implementation
must parse and normalize them at the request/worker boundary into branded or
otherwise narrow internal domain types for account ids, public keys, digests,
operation ids, fingerprints, relayer keys, and network/RPC policy ids. Core
logic should not accept these raw strings directly.

### Auth Rules

`/threshold-ed25519/presign/refill`:

- route class: threshold-session route
- auth: existing threshold-session JWT bearer or cookie auth
- budget: does not consume a signing use
- purpose: prepare message-independent nonce transcripts

`/threshold-ed25519/sign/finalize-and-dispatch`:

- route class: threshold-session route
- auth: existing threshold-session JWT bearer or cookie auth
- budget: consumes one signing use exactly once after request validation and
  before returning a final signature or dispatching. The idempotency key is the
  tuple `(operationId, operationFingerprint, walletSigningSessionId,
  signingDigestB64u)`.
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
  nearNetworkId: string;
  expectedSignerPublicKey: string;
  participantIds: readonly number[];
  clientPresigns: readonly ThresholdEd25519ClientPresignOffer[];
  requestTag: 'background_presign_pool_refill' | 'foreground_presign_pool_refill';
};

type ThresholdEd25519ClientPresignOffer = {
  clientPresignId: string;
  clientVerifyingShareB64u: string;
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
  signerPublicKey: string;
  nearNetworkId: string;
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
  | 'rate_limited'
  | 'capacity_exceeded'
  | 'internal';
```

Server behavior:

- parse and normalize the request at the route boundary
- validate threshold-session auth
- verify `nearAccountId`, `nearNetworkId`, `expectedSignerPublicKey`,
  `relayerKeyId`, participant ids, wallet signing session, RP/runtime scope,
  and active key scope against the authenticated threshold session
- enforce per-wallet-signing-session and global outstanding-presign caps before
  accepting offers
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

type ThresholdEd25519SigningOperation = {
  kind: 'threshold_ed25519_signing_operation_v1';
  operationId: string;
  operationFingerprint: string;
  purpose: 'near_transaction' | 'nep413_message' | 'delegate_action';
};

type ThresholdEd25519FinalizeSignatureOnlyRequest = {
  kind: 'threshold_ed25519_finalize_signature_only_v1';
  operation: ThresholdEd25519SigningOperation;
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  expectedSignerPublicKey: string;
  signingDigestB64u: string;
  clientSignatureShareB64u: string;
};

type ThresholdEd25519FinalizeAndDispatchNearTxRequest = {
  kind: 'threshold_ed25519_finalize_and_dispatch_near_tx_v1';
  operation: ThresholdEd25519SigningOperation;
  presignId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  expectedSignerPublicKey: string;
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
      operationId: string;
      budgetState: 'consumed' | 'already_consumed';
      remainingSigningUses: number;
      signatureB64u: string;
      signerPublicKey: string;
    }
  | {
      ok: true;
      kind: 'threshold_ed25519_dispatched_near_tx_result_v1';
      operationId: string;
      budgetState: 'consumed' | 'already_consumed';
      remainingSigningUses: number;
      signatureB64u: string;
      signerPublicKey: string;
      signedTransactionBorshB64u: string;
      transactionHash: string;
      rpcResult: unknown;
    }
  | {
      ok: false;
      kind: 'threshold_ed25519_finalize_rejected_without_operation_v1';
      code: 'invalid_body' | 'unauthorized' | 'internal';
      message: string;
      budgetState: 'not_consumed';
      presignConsumed: false;
      dispatchState: 'not_attempted';
    }
  | {
      ok: false;
      kind: 'threshold_ed25519_finalize_rejected_for_operation_v1';
      code: ThresholdEd25519FinalizeAndDispatchErrorCode;
      message: string;
      operationId: string;
      budgetState: 'not_consumed' | 'consumed' | 'already_consumed';
      presignConsumed: boolean;
      dispatchState: 'not_attempted' | 'attempted' | 'unknown';
    };

type ThresholdEd25519FinalizeAndDispatchErrorCode =
  | 'invalid_body'
  | 'unauthorized'
  | 'forbidden'
  | 'expired'
  | 'wrong_scope'
  | 'operation_fingerprint_mismatch'
  | 'budget_exhausted'
  | 'budget_operation_conflict'
  | 'presign_unavailable'
  | 'presign_expired'
  | 'presign_consumed'
  | 'digest_mismatch'
  | 'transaction_scope_mismatch'
  | 'transaction_signer_key_mismatch'
  | 'transaction_network_mismatch'
  | 'invalid_signature_share'
  | 'signature_verification_failed'
  | 'dispatch_failed'
  | 'internal';
```

Server behavior:

- parse and normalize the request at the route boundary
- validate threshold-session auth and signing budget availability
- validate the operation id and canonical operation fingerprint against the
  request kind, digest, signer account, network id, relayer key, and transaction
  bytes or signature-only payload
- check the operation budget idempotency state before presign consume. If the
  operation was already consumed and no durable cached result can be returned,
  return `budget_operation_conflict` without consuming another presign.
- validate account, network id, expected signer public key, relayer key,
  participant ids, session scope, wallet signing session, and runtime scope
  against the presign record
- for NEAR dispatch mode, parse `unsignedTransactionBorshB64u`, validate signer
  account, receiver/action policy, signer access key/public key, nonce/network
  expectations, configured RPC policy, and recompute the canonical signing
  digest before comparing it to `signingDigestB64u`
- atomically consume `presignId` only when the stored presign scope matches the
  authenticated request scope
- consume the signing budget with an exactly-once operation key after presign
  consume and before producing relayer signature material
- compute relayer signature share from stored relayer nonces and stored
  commitments
- aggregate the client and relayer shares into a final Ed25519 signature
- verify the final signature against the stored group public key and digest
- for dispatch mode, encode the signed transaction and submit it through the
  configured server NEAR RPC target
- return the final signature plus dispatch result

Finalize outcome rules:

- invalid body, auth failure, wrong scope, operation fingerprint mismatch,
  digest mismatch, transaction-scope mismatch, duplicate consumed operation
  without cached result, and presign unavailable return before budget consume
  and before presign consume
- budget exhaustion or budget operation conflict after presign consume returns
  `budgetState: 'not_consumed'`, `presignConsumed: true`, and
  `dispatchState: 'not_attempted'`
- invalid client signature share after presign consume returns
  `budgetState: 'consumed'`, `presignConsumed: true`, and
  `dispatchState: 'not_attempted'`
- final signature success with signature-only mode returns
  `budgetState: 'consumed'`, `presignConsumed: true`, and remaining budget
- dispatch success returns the final signature, signed transaction bytes,
  transaction hash, RPC result, and remaining budget
- dispatch failure after a signed transaction is built returns
  `budgetState: 'consumed'`, `presignConsumed: true`, and
  `dispatchState: 'attempted'`
- ambiguous network failures after dispatch submission return
  `budgetState: 'consumed'`, `presignConsumed: true`, and
  `dispatchState: 'unknown'`
- duplicate operation retries never decrement budget twice. They may return a
  cached prior result when a durable result exists; otherwise they return
  `budget_operation_conflict` with `budgetState: 'already_consumed'`, the
  original operation id, and no automatic re-dispatch.

Client behavior:

- reserve a ready local presign entry before computing a client signature share
- include a stable operation id and operation fingerprint generated by the
  signing request owner before choosing presign or fallback
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
      clientVerifyingShareB64u: string;
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
      nearNetworkId: string;
      signerPublicKey: string;
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
secrets stay inside the near signer worker. The pool is in-memory only. Worker
restart, page reload, logout, account switch, threshold-session change, wallet
signing session change, relayer key change, participant change, or base/share
change clears the pool and burns local handles. Server-side presign records
whose client handles are lost expire through TTL cleanup.

### Server Presign Record

```ts
type ThresholdEd25519PresignRecord = {
  kind: 'threshold_ed25519_presign_record_v1';
  expiresAtMs: number;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  rpcPolicyId: string;
  rpId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  protocolVersion: 'ed25519_frost_2p_presign_v1';
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
- `takePresignForFinalize(id, expectedScope)` atomically validates the stored
  scope and deletes the record only on an exact scope match
- TTL default is 120 seconds
- expired entries are unusable and may be garbage-collected lazily
- duplicate consume returns `presign_unavailable` or `presign_consumed`
- wrong-scope attempts do not consume the presign or signing budget
- logs may include `presignId` prefixes or hashes, never nonce material or
  signature shares

## Fallback Policy

Fallback is chosen before a client signature share for a presign is sent.
The signing request owner must create one stable operation id and canonical
operation fingerprint before this decision. Both one-RTT presign signing and
two-RTT fallback use the same operation identity.

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
  signature only when the operation fingerprint is unchanged and the caller's
  signing operation idempotency policy permits it
- if the server returns `budget_operation_conflict`, `dispatchState:
  'attempted'`, or `dispatchState: 'unknown'`, the SDK surfaces the result to
  the caller and does not retry automatically

This avoids accidental duplicate transaction dispatch after network failures.

## Security Invariants

- FROST nonces are single-use.
- A presign entry binds one account, one NEAR network, one expected signer
  public key, one threshold session, one wallet signing session, one relayer
  key, one participant set, one RP/runtime scope, one RPC policy, and one group
  public key.
- `presignId` is unguessable and server-generated.
- Finalize binds one operation id and one canonical operation fingerprint to one
  digest and one presign consume.
- Client nonce secrets never leave the near signer worker.
- Server nonce secrets never leave the server-side signing service.
- Finalize burns server presign state atomically before relayer share output can
  be reused.
- The client burns local nonce state once a presigned finalize request is sent.
- Dispatch mode parses the unsigned NEAR transaction, validates signer account,
  signer access key, network/RPC policy, and allowed transaction scope, then
  recomputes the NEAR signing digest from unsigned transaction bytes.
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
  - add `putPresign` and `takePresignForFinalize`
  - implement the presign methods for the existing Ed25519 in-memory,
    Redis/Upstash REST, Postgres, and Cloudflare Durable Object store variants
- `server/src/core/ThresholdService/stores/AuthSessionStore.ts`
  - reuse or extend `consumeUseCountOnce` so finalize-and-dispatch can consume
    signing budget exactly once per operation fingerprint
- `server/src/core/ThresholdService/walletSigningBudget.ts`
  - add the budget projection returned by finalize success and budget-related
    failures
- `server/src/core/ThresholdService/validation.ts`
  - parse and validate presign records and route requests
  - parse operation id/fingerprint, NEAR network id, signer public key, and
    dispatch policy into narrow internal types
- `server/src/core/ThresholdService/nearTransactionDispatch.ts`
  - new or existing-owner helper for unsigned NEAR transaction parsing, signer
    account/key validation, digest recomputation, signed transaction encoding,
    RPC dispatch, and dispatch outcome classification
- `server/src/core/ThresholdService/postgresRecords.ts`
  - add current-shape parser for persisted presign records in the shared
    Ed25519 session table
- `server/src/core/ThresholdService/signingHandlers.ts`
  - expose shared helpers for Ed25519 presign creation, relayer signature-share
    computation, and local/cosigner fanout
  - accept already-parsed route/session inputs from the auth-aware service
    layer when adding presign refill and finalize-and-dispatch behavior
  - refactor existing sign init/finalize to share presign creation and relayer
    share computation helpers
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
  - own threshold-session claim validation outcomes, budget idempotency,
    operation fingerprint enforcement, and policy checks for the new routes
  - wire new presign route handlers into the threshold Ed25519 scheme object
- `server/src/core/ThresholdService/createThresholdSigningService.ts`
  - use the extended Ed25519 session store with presign methods
- `server/src/router/routeDefinitions.ts`
  - add `thresholdSessionRoute` definitions for presign refill and
    finalize-and-dispatch
  - preserve the existing public protocol-state metadata for two-RTT
    continuation routes
- `server/src/router/express/routes/thresholdEd25519.ts`
  - add Express routes
- `server/src/router/cloudflare/routes/thresholdEd25519.ts`
  - add Cloudflare routes
- `server/src/router/cloudflare/durableObjects/thresholdStore.ts`
  - add atomic `takePresignForFinalize` support for Durable Object-backed
    Ed25519 session storage

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
- `client/src/core/signingEngine/session/planning/operationFingerprint.ts`
  - ensure NEAR transaction, NEP-413, and delegate signing fingerprints can be
    reused by presign finalize and depleted-pool fallback
- `client/src/core/signingEngine/session/planning/operationIdBinding.ts`
  - keep caller-provided operation ids bound to one fingerprint across presign
    and fallback attempts
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
- `tests/unit/thresholdEd25519.presignStore.unit.test.ts`
  - atomic consume, wrong-scope non-consume, TTL, and concurrent finalize tests
- `tests/unit/thresholdEd25519.finalizeAndDispatch.unit.test.ts`
  - operation fingerprint, budget exactly-once, dispatch-state, and retry
    outcome tests
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

- [x] Capture current warm Ed25519 signing route count and latency.
- [x] Add request/response/domain type sketches and boundary parsers for route
      bodies, worker messages, presign records, operation identity, dispatch
      requests, and budget projections.
- [x] Reuse existing signing-operation id/fingerprint types for presign and
      fallback paths.
- [x] Add service method signatures that take parsed
      `ThresholdEd25519SessionClaims` and parsed domain request types.
- [x] Add `thresholdSessionRoute` entries for the new routes before wiring handler
      behavior.
- [x] Add static tests that reject invalid presign lifecycle branches.
- [x] Add static tests that reject missing operation fingerprint, missing signer
      public key, nullable runtime scope, invalid dispatch-state combinations, and
      direct raw-shape construction in core helpers.

Validation:

- [x] targeted typecheck for touched TS files
- [x] current threshold Ed25519 active-path test

### Phase 1: Core FROST Helpers

- [x] Add the server-side finalize/aggregate helper in Rust.
- [x] Add tests proving:
  - [x] presign commitments plus later digest produce the same final signature shape
        as the current two-RTT flow
  - [x] mismatched digest fails verification
  - [x] mismatched commitments fail aggregation or verification
- [x] Run constant-time review on new Rust helpers; all scalar/signature operations
      should remain inside FROST/curve libraries.

Validation:

- [x] `cargo test -p signer-core near_threshold`
- [x] near signer wasm build

### Phase 2: Server Presign Store

- [x] Add `ThresholdEd25519PresignRecord`.
- [x] Add `putPresign` and atomic `takePresignForFinalize`.
- [x] Implement storage variants used by local tests and Cloudflare/serverless
      deployments.
- [x] Enforce per-wallet-signing-session and global outstanding-presign caps.
- [x] Add race tests for:
  - [x] double consume
  - [x] wrong-scope non-consume
  - [x] TTL expiry
  - [x] refill-cap enforcement
  - [x] concurrent finalize pressure

Validation:

- [x] store unit tests
- [x] route tests still pass with existing signing path

### Phase 3: Signature-Only Finalize Route

- [x] Add the boundary parser and service method for signature-only one-RTT
      finalize.
- [x] Seed presign records directly in tests instead of depending on the refill
      route.
- [x] Validate operation id/fingerprint, auth scope, presign scope, digest, signer
      public key, participant ids, relayer key, wallet signing session, and runtime
      policy before signature output.
- [x] Consume presign and budget in the specified order.
- [x] Aggregate and verify the final Ed25519 signature on the server.
- [x] Return budget projection and explicit dispatch state.

Validation:

- [x] signature-only route success
- [x] operation fingerprint mismatch rejects
- [x] digest mismatch rejects
- [x] wrong scope rejects without presign or budget consume
- [x] replay/double consume rejects
- [x] budget exactly-once and budget conflict tests
- [x] invalid signature share burns consumed presign and does not dispatch

### Phase 4: Presign Refill Route

- [x] Add route definitions and Express/Cloudflare handlers.
- [x] Add service method that validates threshold-session auth, creates relayer
      commitments, stores presigns, and returns accepted pairs.
- [x] Reuse the same relayer presign creation helper used by two-RTT sign init.

Validation:

- [x] refill success test
- [x] wrong account/session/relayer/participant tests
- [x] malformed commitments test
- [x] no budget decrement on refill
- [x] capacity and per-session cap tests

### Phase 5: Client Presign Pool And Fallback Selector

- [x] Implement pool depth policy:
  - [x] default `targetDepth = 2`
  - [x] default `lowWatermark = 1`
  - [x] max accepted refill count `8`
  - [x] entry TTL follows server expiry
- [x] Implement generation invalidation on:
  - [x] threshold session change
  - [x] wallet signing session change
  - [x] relayer key change
  - [x] participant id change
  - [x] client base/share change
- [x] Implement worker-local in-memory durability rules:
  - [x] clear on worker restart or page reload
  - [x] clear on logout or account switch
  - [x] clear on threshold-session or wallet-signing-session change
- [x] Implement fallback selector:
  - [x] pool hit -> one-RTT
  - [x] pool miss -> schedule refill and use two-RTT
- [x] Keep one stable operation id and fingerprint across presign and fallback
      attempts.

Validation:

- [x] pool lifecycle unit tests
- [x] stale generation tests
- [x] concurrent refill suppression tests
- [x] local nonce burn/zeroization tests
- [x] operation id/fingerprint binding tests

### Phase 6: NEAR Finalize-And-Dispatch And Default Signing Path

- [x] Add route definitions and Express/Cloudflare handlers.
- [x] Add service method that parses and validates unsigned NEAR transaction bytes,
      consumes presign and budget, computes relayer share, aggregates, verifies,
      signs, and dispatches.
- [x] Validate signer account, expected signer public key/access key, network id,
      configured RPC policy, nonce expectations, relayer key, operation fingerprint,
      and digest.
- [x] Wire the Phase 3 signature-only branch into NEP-413 and delegate signing
      flows when a ready presign entry exists.
- [x] Update warm Ed25519 single-transaction signing:
  - [x] attempt one-RTT finalize-and-dispatch when a ready presign entry exists
  - [x] fallback to current two-RTT sign path when the pool is depleted/refilling
  - [x] schedule refill after success or pool miss
- [x] Preserve existing result shapes expected by `signTransactionsWithActions`.
- [x] Add metrics:
  - [x] `ed25519_presign_pool_hit`
  - [x] `ed25519_presign_pool_miss`
  - [x] `ed25519_presign_refill_in_flight`
  - [x] `ed25519_one_rtt_finalize_ms`
  - [x] `ed25519_two_rtt_fallback_ms`

Validation:

- [x] dispatch route success
- [x] transaction signer/account/key/network mismatch rejects
- [x] ambiguous dispatch state is represented in the response
- [x] signature-only NEP-413/delegate presign helper tests
- [x] single-transaction pool-hit finalize-and-dispatch helper test
- [x] single-transaction pool-miss fallback helper test
- [x] multi-transaction batch fallback helper test
- [x] client refill runner test
- [x] opaque worker nonce-handle burn wrapper test
- [x] active-path tests
- [x] warm-session login/unlock tests
- [x] Email OTP warm-session tests
- [x] end-to-end transaction signing tests with pool hit and pool miss

### Phase 7: Cleanup, Hardening, And Benchmarks

- [x] Remove temporary duplicate helper paths introduced during implementation.
- [x] Keep the two-RTT routes as the depleted-pool fallback.
- [x] Share helper code between presign refill and two-RTT sign init.
- [x] Share helper code between finalize-and-dispatch and two-RTT sign finalize.
- [x] Update docs and benchmark tables.
- [x] Add load tests for end-to-end pool hit/miss/refill behavior and serverless
      double-consume pressure.

Validation:

- [x] `pnpm -C tests test:threshold-ed25519:active-path`
- [x] targeted route/unit tests
- [x] load-test scenario for pool hit/miss/refill
- [x] benchmark comparison against the Phase 0 baseline

## Benchmark Plan

Measure these scenarios before and after:

- current warm sign with `/sign/init` + `/sign/finalize`
- warm sign with presign pool hit and server dispatch
- warm sign with presign pool hit and signature-only finalize
- warm sign with empty pool and two-RTT fallback
- concurrent sign attempts with one ready presign
- expired presign cleanup
- cross-worker/serverless double-consume race
- duplicate operation retry with the same fingerprint
- duplicate operation id with a different fingerprint
- server dispatch failure and ambiguous RPC result classification

Metrics:

- visible client signing latency
- route count per sign
- presign refill latency
- finalize-and-dispatch latency
- pool hit ratio
- pool miss fallback latency
- presign consume replay failures
- budget exactly-once replay outcomes
- dispatch success/failure latency
- ambiguous dispatch count

Expected result:

- warm pool-hit transaction signing drops from two visible MPC RTTs to one
  visible RTT
- cold or depleted-pool signing remains close to current latency for that sign
- refill makes subsequent signs return to the one-RTT path

## Todo

- [x] Add boundary parsers and static fixtures for request/response, lifecycle,
      operation identity, dispatch state, and presign records.
- [x] Add Rust server-side Ed25519 aggregate/finalize helper.
- [x] Add server presign record, cap policy, and atomic
      `takePresignForFinalize` store methods.
- [x] Add signature-only `/threshold-ed25519/sign/finalize-and-dispatch`.
- [x] Add finalize budget exactly-once and retry outcome tests.
- [x] Add `/threshold-ed25519/presign/refill`.
- [x] Add worker-local client nonce handle pool.
- [x] Add TypeScript Ed25519 presign pool lifecycle module.
- [x] Add NEAR transaction parser/validator/dispatcher for server dispatch.
- [x] Switch single-transaction signing default to one-RTT pool-hit path.
- [x] Keep two-RTT signing as depleted-pool fallback.
- [x] Explicitly codify multi-transaction batch fallback behavior.
- [x] Add pool hit/miss/refill metrics.
- [x] Add concurrency, retry, dispatch-state, benchmark, and load tests.
- [x] Update route auth and SDK docs.

## Phase 8: Security Hardening

This phase closes the remaining security review issues before the one-RTT path
is treated as the default production behavior.

### Finding 1: Signature-Only Finalize Needs Server-Verifiable Intent

Risk: high.

The presign path moves nonce-preparation authority from digest-scoped
`mpcSessionId` to threshold-session auth. That is sound for background
message-independent refill, but finalize is the first digest-specific operation
in the one-RTT path. The NEAR transaction route sends unsigned transaction bytes
and lets the server recompute the canonical digest. Signature-only finalize
needs the same level of server-verifiable intent for NEP-413 and delegate
actions. A client-provided fingerprint alone cannot prove the user-authorized
payload.

Todo:

- [x] Replace digest-only signature-only finalize with typed NEP-413 and
      delegate finalize contracts, or require a stored authorized operation record.
- [x] For NEP-413, parse typed account, message, recipient, nonce, optional
      state, network id, relayer key, signer public key, and scope at the route
      boundary.
- [x] For delegate actions, parse the typed delegate action payload at the route
      boundary or consume a stored authorized delegate operation record.
- [x] Recompute the NEP-413 and delegate signing digests on the server before
      presign consume.
- [x] Recompute the canonical domain operation fingerprint on the server before
      presign consume.
- [x] Stored authorization records are not used; typed finalize contracts provide
      the server-verifiable intent consumed before presign consume.
- [x] Reject signature-only requests that carry only digest, operation id,
      fingerprint, and client share.
- [x] Add tests that NEP-413 finalize rejects message, recipient, nonce, state,
      account, digest, and fingerprint mismatches.
- [x] Add tests that delegate finalize rejects payload, signer, account, digest,
      and fingerprint mismatches.
- [x] Add tests that missing or wrong-scope operation intent returns before
      presign consume and before budget consume.

### Finding 2: Operation Fingerprint Semantics Must Be Canonical

Risk: medium.

The client computes domain fingerprints from transaction, NEP-413, and delegate
payloads. The server must compare against the same domain identity. A hash of
finalize transport fields is useful as request-integrity metadata, but it must
stay separate from the domain operation fingerprint used by user intent, budget
idempotency, nonce coordination, operation-id binding, and retry policy.

Todo:

- [x] Define one canonical fingerprint builder for `near_transaction`.
- [x] Define one canonical fingerprint builder for `nep413_message`.
- [x] Define one canonical fingerprint builder for `delegate_action`.
- [x] Share the canonical field list, JSON normalization, byte encoding, network
      id, signer account, signer public key, relayer key, and purpose string between
      client and server.
- [x] Make finalize compare `operation.operationFingerprint` against the
      recomputed domain fingerprint.
- [x] Add a separate `requestIntegrityHash` or route-local equivalent if the
      finalize request needs transport-field tamper detection.
- [x] Keep request-integrity metadata out of budget idempotency and operation-id
      binding.
- [x] Keep budget idempotency keyed by `(operationId, operationFingerprint,
  walletSigningSessionId, signingDigestB64u)`.
- [x] Add client/server fixture tests for matching NEAR transaction, NEP-413,
      and delegate fingerprints.
- [x] Add mismatch tests proving signed domain-field changes alter the canonical
      fingerprint.
- [x] Add tests proving transport-only field changes do not alter the canonical
      domain fingerprint.
- [x] Add duplicate-operation tests where the same operation id with a different
      domain fingerprint fails before presign consume.

### Finding 3: Presign Refill Adds An Authenticated Resource Surface

Risk: low to medium.

Refill intentionally does not consume signing budget because it prepares
message-independent nonce transcripts. That creates a resource surface for any
authenticated threshold session. Caps, TTL, atomic consume, and log scrubbing
are required. Explicit rate limits and load-test acceptance criteria are also
required because refill can allocate server nonce material and durable state
before a user signs.

Todo:

- [x] Enforce refill rate limits by wallet signing session.
- [x] Enforce refill rate limits by threshold session.
- [x] Enforce refill rate limits by account and relayer key.
- [x] Enforce refill rate limits by source IP or deployment-equivalent request
      origin.
- [x] Check outstanding-presign caps before creating relayer nonce material.
- [x] Keep `max accepted refill count = 8`, default pool target depth `2`, and
      short TTL unless benchmark data justifies a smaller limit.
- [x] Add client backoff after `capacity_exceeded`, repeated `wrong_scope`, or
      repeated refill failures.
- [x] Emit metrics for accepted offers, rejected offers, rate-limit rejects,
      capacity rejects, outstanding presign count, TTL cleanup, and double-consume
      attempts.
- [x] Add load tests for authenticated refill pressure.
- [x] Add load tests for concurrent finalize pressure.
- [x] Add load tests for serverless double-consume pressure.
- [x] Add wrong-scope pressure tests proving wrong-scope attempts do not consume
      presigns or budget.
- [x] Verify logs and metrics omit nonce material, signature shares, raw client
      share material, and full signed transaction bytes.
- [x] Treat Phase 8 tests as a security acceptance gate before defaulting
      one-RTT signing in production.

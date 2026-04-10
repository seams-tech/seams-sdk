# SDK/Server Refactor Plan: Replace The Legacy Threshold-ECDSA Seam With `ecdsa-hss`

Date created: April 9, 2026

## Summary

The repo's current threshold ECDSA product path is still built around a legacy
bootstrap seam:

- the client derives `clientVerifyingShareB64u`
- the server derives `relayerKeyId` and the relayer share from that value plus
  the relayer master secret
- registration, link-device, login warm-up, session activation, authorize, and
  sign orchestration all treat that pair as the ECDSA threshold identity

That seam is the wrong source of truth for `ecdsa-hss`.

`ecdsa-hss` is supposed to be the source of truth for:

- one canonical secp256k1 key
- one threshold-signing identity
- one export identity
- one server-blind staged bootstrap path

The refactor goal is therefore:

- remove the old `clientVerifyingShareB64u -> relayerKeyId -> relayer share`
  bootstrap identity seam
- replace it with a staged `ecdsa-hss` bootstrap flow
- keep the existing presign/sign runtime only where it remains a clean backend
  implementation detail
- stop exposing legacy bootstrap assumptions at the SDK/server boundary

This plan is product-facing. It is not the crate-only plan in
[implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/implementation-plan.md).

## Architectural Stance

This refactor should follow these rules:

1. `ecdsa-hss` becomes the only source of new EVM threshold key material.
2. The old atomic `/threshold-ecdsa/bootstrap` seam is removed, not preserved
   indefinitely beside a new one.
3. The sign-time backend may be reused, but only as an internal consumer of
   `ecdsa-hss`-derived material.
4. The product-facing threshold ECDSA identity stops being
   `clientVerifyingShareB64u + relayerKeyId`.
5. Export remains explicit and uses the same canonical key as threshold
   signing.
6. Breaking changes are acceptable. We should not keep a long-lived dual-stack
   API just to protect old assumptions during development.

## Current Legacy Seam

### Client-Side Shape Today

The current client path still bootstraps threshold ECDSA from the legacy share
lane:

- [bootstrapEcdsaSession.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts)
  derives `clientVerifyingShareB64u` from passkey material and posts it to
  `/threshold-ecdsa/bootstrap`
- [thresholdActivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/thresholdActivation.ts)
  persists `relayerKeyId`, `clientVerifyingShareB64u`,
  `thresholdEcdsaPublicKeyB64u`, and `relayerVerifyingShareB64u` as the key ref
  identity
- [thresholdEcdsaCoordinator.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts)
  keys presign pools and sign orchestration off `relayerUrl`, `relayerKeyId`,
  `clientVerifyingShareB64u`, and `participantIds`
- [registration.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/registration.ts),
  [login.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/login.ts),
  and
  [evm/linkDeviceThresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts)
  all repeat the same legacy bootstrap assumptions

### Server-Side Shape Today

The current server path is also anchored on that same legacy seam:

- [types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/types.ts)
  defines `ThresholdEcdsaBootstrapRequest` and related requests around
  `clientVerifyingShareB64u`
- [thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/thresholdEcdsa.ts)
  and
  [thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/thresholdEcdsa.ts)
  expose `/threshold-ecdsa/bootstrap` as the public key-material entrypoint
- [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  still derives the relayer share and relayer verifying share from the relayer
  master secret plus `clientVerifyingShareB64u`
- [ecdsaSigningHandlers.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ecdsaSigningHandlers.ts)
  re-derives relayer signing material on demand from `relayerKeyId`
- [AuthService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/AuthService.ts)
  repeats the legacy seam during registration, link-device, and session minting

### What This Means

The old seam is duplicated across:

- product account creation
- link-device flows
- login warm-up
- runtime session activation
- presign pool identity
- sign authorization
- server-side relayer share derivation

That duplication is the main reason the implementation is hard to reason about.

## What The New Seam Should Be

The public SDK/server seam should move to one `ecdsa-hss` threshold identity.

### Product-Facing Identity

For a live EVM threshold key, the product-facing identity should be:

- `ecdsaThresholdKeyId`
- `thresholdEcdsaPublicKeyB64u`
- `ethereumAddress`
- `participantIds`
- session credentials and policy metadata as needed

This becomes the stable identity at the product boundary.

### Client-Local Material

Client-local bootstrap and signing material should stay client-local:

- client root input
- client-side `ecdsa-hss` request inputs
- client additive/signing share material
- any client verifying-share derivative needed only to drive the current
  backend

This material may exist in runtime state, but it should not remain the public
identity seam used by every route and store.

### Server-Only Material

Server-only relayer material should become a first-class persisted key record,
not something that is statelessly re-derived forever from the legacy seam.

At minimum, the server should own:

- `ecdsaThresholdKeyId`
- key/account binding fields
- `thresholdEcdsaPublicKeyB64u`
- `ethereumAddress`
- fixed participant IDs
- relayer-side backend input required by the current signer backend
- relayer verifying share only if the backend still needs it

## Preferred Endpoint Shape

The clean endpoint shape is to replace the old atomic bootstrap with a staged
`ecdsa-hss` bootstrap flow, mirroring the successful Ed25519 HSS pattern.

### New Staged Bootstrap Endpoints

Introduce:

- `POST /threshold-ecdsa/hss/prepare`
- `POST /threshold-ecdsa/hss/respond`
- `POST /threshold-ecdsa/hss/finalize`

These endpoints should become the only public bootstrap path for new EVM
threshold keys.

They should cover the operation variants we actually need:

- registration bootstrap
- session bootstrap
- explicit export

### Endpoints To Retire

Retire:

- `POST /threshold-ecdsa/bootstrap`

Then remove the legacy key-material assumptions from:

- `POST /threshold-ecdsa/authorize`
- `POST /threshold-ecdsa/presign/init`

Those endpoints may remain, but their request shape should stop depending on:

- `clientVerifyingShareB64u`
- `relayerKeyId`

Instead they should key off:

- `ecdsaThresholdKeyId`
- `mpcSessionId`
- session-bound claims that already identify the threshold key

## Target Runtime Architecture

### 1. `ecdsa-hss` Owns Bootstrap And Export

The SDK and server should treat `ecdsa-hss` as the only source of:

- canonical EVM key derivation
- threshold share derivation
- export-capable output
- threshold identity creation

There should be no separate legacy ECDSA keygen helper beside it.

### 2. Current Signer Backend Remains An Internal Consumer

The repo's current threshold-signatures-based signer backend is still useful.

We should keep reusing:

- signer-core threshold ECDSA
- additive-share mapping
- presign/sign orchestration

But those become internal consumers of `ecdsa-hss` output, not the design
source of truth.

### 3. One Persisted EVM Threshold Key Record

Add a server-owned key record specifically for the integrated EVM threshold key
path.

This record should replace the old implicit identity split across:

- `clientVerifyingShareB64u`
- `relayerKeyId`
- on-demand relayer share derivation

The record should be the thing that authorize/presign/sign look up.

### 4. One Client Activation Shape

Refactor the client threshold ECDSA key ref so it is keyed primarily by:

- `ecdsaThresholdKeyId`
- `thresholdEcdsaPublicKeyB64u`
- `ethereumAddress`

Any retained `clientVerifyingShareB64u` should become a backend-integration
detail, not the canonical identity at the SDK boundary.

## Clean Refactor Strategy

The elegant implementation strategy is:

1. Replace the bootstrap seam first.
2. Move server persistence to an explicit `ecdsa-hss` key record.
3. Re-key authorize/presign on that record.
4. Only then delete the remaining legacy fields and helpers.

Do not start by rewriting the entire sign runtime.

The current sign runtime is not the architectural problem. The key-material
bootstrap seam is.

## Refactor Risks

### Risk 1: Recreating The Legacy Seam Under A New Name

If the new flow still depends on `clientVerifyingShareB64u` and `relayerKeyId`
as the product-facing identity, then we have only wrapped the old design.

Mitigation:

- make `ecdsaThresholdKeyId` the public identity
- move verifying shares behind the integration layer

### Risk 2: Building A Second Bootstrap Stack

If the new staged endpoints are added but the old bootstrap endpoint remains as
an equally valid production path, the codebase stays confused.

Mitigation:

- make staged `ecdsa-hss` bootstrap the only new path
- schedule deletion of `/threshold-ecdsa/bootstrap`

### Risk 3: Letting Server-Blindness Drift During Integration

The server should never need the canonical private key for non-export flows.

Mitigation:

- keep staged ceremony state explicit
- keep relayer-only persisted material separate from export-capable output
- use the existing `ecdsa-hss` specs and FV scope as the design boundary

## Phased Todo List

### Phase 0: Freeze The Integration Shape

Goal:

- decide the exact public seam and stop letting the legacy seam leak forward

Todo:

- [x] freeze the new public threshold ECDSA identity as:
      `ecdsaThresholdKeyId`, `thresholdEcdsaPublicKeyB64u`, `ethereumAddress`,
      `participantIds`
- [x] freeze the staged endpoint set:
      `/threshold-ecdsa/hss/prepare`, `/respond`, `/finalize`
- [x] decide which existing sign-time endpoints keep their paths and which get
      request-shape changes
- [x] define the server-owned `ecdsa-hss` EVM key record shape in
      [server/src/core/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/types.ts)
- [x] define the new client key-ref shape in
      [client/src/core/signingEngine/interfaces/signing.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/interfaces/signing.ts)
- [x] explicitly mark `clientVerifyingShareB64u` and `relayerKeyId` as
      backend-integration details, not product identity

### Phase 1: Build The Staged Server Bootstrap

Goal:

- add the real server-side `ecdsa-hss` staged bootstrap flow

Todo:

- [x] add server request/response types for staged ECDSA HSS bootstrap in
      [server/src/core/types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/types.ts)
- [x] add staged route definitions in:
      - [server/src/router/cloudflare/routes/thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/thresholdEcdsa.ts)
      - [server/src/router/express/routes/thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/thresholdEcdsa.ts)
- [x] add `ecdsa-hss` prepare/respond/finalize service methods in
      [server/src/core/ThresholdService/ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
- [x] add a server-owned ceremony store for staged `ecdsa-hss` bootstrap state
- [x] bind staged operations explicitly:
      - registration bootstrap
      - session bootstrap
      - explicit export
- [x] ensure non-export finalize never emits export-capable output

### Phase 2: Persist The New Server-Owned Key Record

Goal:

- stop relying on stateless relayer share derivation from the legacy seam

Todo:

- [x] add a persisted `ecdsa-hss` EVM key record store
- [x] persist relayer-side backend input keyed by `ecdsaThresholdKeyId`
- [x] persist public identity:
      `thresholdEcdsaPublicKeyB64u`, `ethereumAddress`, `participantIds`
- [x] make account binding explicit:
      `userId`, `rpId`, key version, scheme id
- [x] stop treating `relayerKeyId = hash(userId, rpId, clientVerifyingShareB64u)`
      as the canonical server key identity

### Phase 3: Refactor Client Bootstrap And Activation

Goal:

- move the client onto the staged `ecdsa-hss` bootstrap flow

Todo:

- [x] add client RPC helpers for the staged ECDSA HSS endpoints in
      [client/src/core/rpcClients/relayer/thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/rpcClients/relayer/thresholdEcdsa.ts)
- [x] replace the atomic bootstrap flow in
      [client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts)
      with staged `ecdsa-hss` bootstrap
- [x] change
      [client/src/core/signingEngine/orchestration/thresholdActivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/thresholdActivation.ts)
      to activate from `ecdsaThresholdKeyId`-based identity
- [x] update
      [client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts)
      and
      [client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts)
      to persist the new identity shape
- [x] keep any client verifying-share derivative only where the current backend
      still strictly needs it

### Phase 4: Re-Key Authorize And Sign Orchestration

Goal:

- stop requiring the legacy seam on every authorize/presign call

Todo:

- [x] change authorize request types to key off `ecdsaThresholdKeyId` or the
      active threshold session identity
- [x] change presign-init request types to key off `ecdsaThresholdKeyId`
      instead of `clientVerifyingShareB64u`
- [x] update
      [client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts)
      so pool keys and runtime identity use the new threshold key id
- [x] update
      [server/src/core/ThresholdService/ecdsaSigningHandlers.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ecdsaSigningHandlers.ts)
      to load relayer-side backend input from the persisted `ecdsa-hss` key
      record instead of re-deriving it from the legacy seam
- [x] preserve the existing signer-core presign/sign runtime unless a concrete
      incompatibility forces deeper changes

### Phase 5: Migrate Registration, Link-Device, And Login Warm-Up

Goal:

- make all product key-creation entrypoints use the new staged bootstrap

Todo:

- [x] replace
      `ecdsaRegistrationKeygenFromClientVerifyingShare(...)`
      usage in
      [server/src/core/AuthService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/AuthService.ts)
      with staged `ecdsa-hss` registration bootstrap
- [x] replace
      `mintEcdsaSessionFromRegistration(...)`
      with staged `ecdsa-hss` session bootstrap output
- [x] update
      [client/src/core/TatchiPasskey/registration.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/registration.ts)
      to use the staged `ecdsa-hss` bootstrap as the source of truth for new
      ECDSA identity
- [x] update
      [client/src/core/TatchiPasskey/login.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/login.ts)
      to warm sessions from staged `ecdsa-hss` bootstrap
- [x] update link-device and recovery flows to consume the same staged ECDSA
      HSS bootstrap path

### Phase 6: Delete The Legacy Seam

Goal:

- remove the old bootstrap identity model from the codebase

Todo:

- [x] delete `/threshold-ecdsa/bootstrap`
- [x] delete the old bootstrap request/response types centered on
      `clientVerifyingShareB64u`
- [x] delete
      `ecdsaRegistrationKeygenFromClientVerifyingShare(...)`
- [x] narrow the remaining stateless relayer derivation path to intentional
      first-time bootstrap only and stop using it for existing-key
      resume/export
- [x] remove legacy key-ref/session fields that are no longer needed at the
      product boundary
- [x] remove any temporary dual-path shims added during the refactor

### Phase 7: Validation And Acceptance

Goal:

- prove the product path now really uses `ecdsa-hss`

Todo:

- [x] add SDK unit coverage showing source-flow continuity for:
      - registration-sourced one-key ECDSA session -> explicit export
      - login-sourced one-key ECDSA session -> explicit export
      - link-device/manual-bootstrap one-key ECDSA session -> explicit export
- [x] add end-to-end tests for:
      - registration -> bootstrap -> sign -> export
      - login -> bootstrap -> sign -> export
- [x] add end-to-end tests for:
      - link-device/manual-bootstrap -> sign -> export
- [x] add negative tests showing signing flows cannot extract canonical export
      output
- [x] add server-store tests showing the server persists relayer-side backend
      material without persisting forbidden export-capable output
- [x] verify the SDK no longer depends on `clientVerifyingShareB64u` as the
      public threshold ECDSA identity
- [x] verify the server no longer derives threshold key identity from the
      legacy hash binding

Current acceptance status:

- [x] relayer harness coverage is green for staged bootstrap -> authorize ->
      presign -> sign
- [x] relayer harness coverage is green for coordinator forwarding and
      stale-session recovery
- [x] relayer harness coverage is green for staged bootstrap -> sign ->
      explicit export
- [x] relayer harness coverage is green for deferred first-time
      `session_bootstrap` -> sign -> explicit export, followed by persisted
      resume/export reuse under the same `ecdsaThresholdKeyId`
- [x] SDK unit coverage is green for source-flow export continuity from:
      - registration
      - login
      - link-device/manual-bootstrap
- [x] browser/source-flow acceptance is green for:
      - registration -> bootstrap -> sign -> export
      - login -> bootstrap -> sign -> export
- [x] browser/source-flow acceptance is green for:
      - link-device/manual-bootstrap -> sign -> export

### Phase 8: Replace Cleartext Bootstrap Transport

Goal:

- replace cleartext client root-share transport with the real hidden-eval
  distributed `ecdsa-hss` bootstrap flow

Todo:

- [x] isolate staged ECDSA HSS transport parsing/encoding behind dedicated
      transport helpers so the cleartext path is not smeared through
      `ThresholdSigningService.ts`
- [x] define the hidden-eval client request/response/finalize message shape at
      the SDK/server boundary
- [x] audit the existing Ed25519 HSS staged runtime and freeze the exact ECDSA
      hidden-eval runtime API surface we need to mirror
- [x] add generated worker request/response type slots for staged ECDSA
      hidden-eval client operations
- [x] add client-side ECDSA hidden-eval wasm bridge scaffolding that fails
      closed until the real wasm primitive is implemented
- [x] expose fail-closed staged ECDSA hidden-eval client exports from the real
      `hss_client_signer` wasm crate so the runtime seam exists end-to-end
- [x] expose fail-closed staged ECDSA hidden-eval server exports and
      `ethSignerWasm.ts` wrappers so the server runtime seam exists end-to-end
- [x] replace cleartext `yClient32LeB64u` request transport with hidden-eval
      client messages
- [x] replace server-side direct `base64UrlDecode(yClient32LeB64u)` bootstrap
      handling with hidden-eval message handling
- [x] prove non-export staged transport no longer carries raw client root
      material anywhere on the staged `prepare/respond/finalize` SDK/server wire
- [x] decide deferred first-time ECDSA bootstrap remains supported and retain
      the narrowed first-bootstrap derivation path intentionally

Notes:

- the hidden-eval wire shape is now frozen as opaque
  `clientEvalRequestB64u`, `serverEvalResponseB64u`, and
  `clientEvalFinalizeB64u` envelopes in the SDK/server transport helpers
- the live SDK/server staged bootstrap path now uses those opaque hidden-eval
  envelopes across:
  - relayer harness acceptance
  - browser registration/login bootstrap -> sign -> export acceptance
  - browser sealed-refresh ECDSA rehydration acceptance
 - existing-key `session_bootstrap` and `explicit_key_export` now load
   server-owned persisted key material instead of re-deriving relayer input
   from the server master secret:
   - `relayerRootShare32B64u` for staged HSS bootstrap/export
   - `relayerBackendInputB64u` for the current sign-time backend
- the runtime pattern to mirror is now explicit from the existing Ed25519 HSS
  flow:
  - client worker/wasm:
    - prepare ECDSA HSS client session
    - prepare ECDSA HSS client request
    - open ECDSA HSS client output
    - open ECDSA HSS export output
 - the remaining live stateless relayer derivation is now intentionally
   narrowed to first-time bootstrap only:
   - `deriveEcdsaKeyMaterialForFirstBootstrapFromClientRootShare(...)`
   in
   [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
   it is intentionally used for:
   - `registration_bootstrap`
   - first-time deferred `session_bootstrap` when no `ecdsaThresholdKeyId`
     exists yet
   this is now product behavior, not leftover compatibility code
  - server wasm:
    - prepare ECDSA HSS server session
    - prepare ECDSA HSS server ceremony
    - finalize ECDSA HSS report
    - open ECDSA HSS server output
- the staged transport proof is now enforced at the helper boundary:
  - the live `prepare/respond/finalize` path only accepts hidden-eval envelopes
    carrying `clientEvalRequestB64u`, `serverEvalResponseB64u`, and
    `clientEvalFinalizeB64u`
  - the removed cleartext staged envelope shape
    (`threshold_ecdsa_hss_client_request_v1` /
    `threshold_ecdsa_hss_server_response_v1`) is no longer present in the live
    helper surface and is rejected by the server hidden-eval parsers
  - guard tests freeze the exact staged envelope keys so raw
    `yClient32LeB64u` / `clientRootShare32B64u` cannot silently reappear in the
    staged transport
- scope note:
  - this proof is about the staged `prepare/respond/finalize` transport only
  - registration/account-recovery payloads still carry
    `threshold_ecdsa.client_root_share32_b64u` at their own product boundary,
    which is separate from the staged hidden-eval seam

## ECDSA Test Audit

The current threshold ECDSA test surface is in three buckets.

- [x] review the current threshold ECDSA test surface and classify keep vs
      update vs backend-internal ownership

### Keep

These still match the current design well enough and should remain:

- `tests/relayer/threshold-ecdsa.signature-harness.test.ts`
- `tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`
- `tests/unit/thresholdEcdsa.integratedKeyStore.unit.test.ts`
- `tests/unit/thresholdEcdsa.oneKeySourceFlowExport.unit.test.ts`
- `tests/unit/thresholdEcdsa.noLegacySurface.guard.unit.test.ts`
- `tests/unit/thresholdEcdsa.registrationBootstrapParity.unit.test.ts`

### Update

These are still useful, but they expose too much of the old public seam or use
assertions/messages that should now be centered on `ecdsaThresholdKeyId` and
root-share/staged bootstrap behavior:

- `tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
- `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
- `tests/helpers/thresholdEcdsaTempoFlow.ts`

### Keep As Backend-Internal

These are acceptable as long as they are clearly treated as backend-internal
tests, not product-boundary identity tests:

- `tests/relayer/threshold-ecdsa.durable-stores.test.ts`
- `tests/unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts`
- `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`
- `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`
- `tests/unit/thresholdEcdsa.requestTimeout.unit.test.ts`
- `tests/unit/thresholdEcdsaSessionStore.lanes.unit.test.ts`
- `tests/unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts`

### Tightening Todo

- [x] update `tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts` so warm-up
      assertions stop treating `clientVerifyingShareB64u` as the public bootstrap
      input and instead assert the staged/root-share bootstrap seam plus
      canonical `ecdsaThresholdKeyId`
- [x] move `tests/helpers/thresholdEcdsaTempoFlow.ts` onto managed registration
      transport and real threshold-session JWT issuance so the Tempo harness is
      exercising the current registration seam instead of the removed direct
      bootstrap path
- [x] update `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts` and
      `tests/helpers/thresholdEcdsaTempoFlow.ts` so public assertions center on
      `ecdsaThresholdKeyId`, `thresholdEcdsaPublicKeyB64u`, and `ethereumAddress`,
      leaving `relayerKeyId` and `clientVerifyingShareB64u` only as
      backend-internal details where strictly needed
- [x] update `tests/e2e/thresholdEcdsa.tempoSigning.test.ts` so bootstrap/sign
      acceptance checks use the staged `ecdsa-hss` identity seam rather than the
      old bootstrap-era identity assumptions
- [x] update `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts` to
      add real browser-level source-flow export acceptance after the existing
      registration-finalize seed-output blocker is fixed
- [x] rename or clarify backend-store/presign-pool test fixtures so any use of
      `relayerKeyId` is clearly documented as backend-internal, not product
      identity
- [x] remove or replace any remaining test assertion that treats
      `clientVerifyingShareB64u` as the canonical product-facing ECDSA identity

Current test-tightening blockers:

- Browser-level source-flow export acceptance is still outstanding in:
  - link-device source flows

## Recommended Implementation Order

The clean implementation order is:

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7

The key rule is:

- do not start by changing signer-core
- do not keep the legacy bootstrap seam alive longer than necessary
- do not resume broad SDK rollout until Phases 1-4 are coherent end-to-end

## Success Criteria

This refactor is successful only when all of these are true:

- the SDK/server public threshold ECDSA seam is `ecdsa-hss`-based
- the old `clientVerifyingShareB64u` bootstrap identity seam is gone
- new EVM threshold keys are created only through staged `ecdsa-hss` bootstrap
- threshold signing and export refer to the same canonical key
- the server remains blind to the canonical private key outside explicit export
  output to the client

## Review Findings And Tightening Todo

Review summary:

- File placement is mostly corrected now:
  - ECDSA-specific link-device persistence moved to
    [client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts),
    which is the right boundary for EVM threshold signing.
  - staged ECDSA relay RPC helpers live in
    [client/src/core/rpcClients/relayer/thresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/rpcClients/relayer/thresholdEcdsa.ts),
    which is also the right boundary.
  - some EVM-touching flows still live under `near/`, but those are account
    lifecycle owners rather than signer implementations, so they are acceptable
    if they do not become signer-logic dumping grounds.
- The implementation is materially tighter now:
  - finalize is bound to the staged request/response envelope
  - relayer backend input is persisted as real backend share material
  - sign-time presign/finalize no longer need to re-derive relayer share state
    from `relayerKeyId`
  - the dead canonical export resolver seam is gone
  - the public threshold ECDSA key ref now requires `ecdsaThresholdKeyId`
- The remaining open shortcut is narrower:
  - the staged bootstrap seam now uses hidden-eval envelopes on the
    SDK/server wire, but the broader server-blind secrecy claim remains scoped
    to the agreed staged-boundary model rather than a stronger end-to-end proof

Findings:

1. The staged ECDSA HSS bootstrap still is not the full distributed root-share
   `ecdsa-hss` transport.
   - [client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts:34](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts#L34)
   - [server/src/core/ThresholdService/ThresholdSigningService.ts:2590](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts#L2590)
   - The client now sends only hidden-eval staged envelopes carrying
     `clientEvalRequestB64u`, and finalize is bound to the staged server
     response plus `clientEvalFinalizeB64u`.
   - The server derives threshold ECDSA material only after opening the staged
     server output inside the server runtime, and persists real relayer-side
     backend input keyed by `ecdsaThresholdKeyId`.
   - So the raw client root share is no longer on the staged SDK/server wire,
     but we still have not proven a stronger secrecy claim than the agreed
     server-visible staged-boundary scope.

2. The remaining server-side work is now focused on replacing the staged
   bootstrap payload with true distributed `ecdsa-hss` transport, not on sign
   runtime identity.
   - [server/src/core/ThresholdService/ThresholdSigningService.ts:2026](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts#L2026)
   - [server/src/core/ThresholdService/ThresholdSigningService.ts:2525](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts#L2525)
   - [server/src/core/ThresholdService/ecdsaSigningHandlers.ts:632](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ecdsaSigningHandlers.ts#L632)
   - `relayerBackendInputB64u` now stores the relayer threshold signing share
     bytes.
   - Presign init now loads that persisted backend input instead of re-deriving
     relayer share state from `THRESHOLD_SECP256K1_MASTER_SECRET_B64U` and
     `relayerKeyId`.
   - Sign finalize now uses persisted group public key identity carried through
     the signing session instead of re-deriving relayer verifying-share state.

3. The old host-supplied canonical export artifact resolver seam has been
   removed.
   - [client/src/core/TatchiPasskey/thresholdEcdsaCanonicalExportArtifact.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/thresholdEcdsaCanonicalExportArtifact.ts)
   - [client/src/core/TatchiPasskey/interfaces.ts:193](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/interfaces.ts#L193)
   - [client/src/core/TatchiPasskey/index.ts:255](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/index.ts#L255)
   - Registration/login were already no longer using it as the source of truth.
   - The helper file and public API seam are now deleted.

4. The public `threshold-ecdsa-secp256k1` key ref now requires
   `ecdsaThresholdKeyId`.
   - [client/src/core/signingEngine/interfaces/signing.ts:23](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/interfaces/signing.ts#L23)
   - `ecdsaThresholdKeyId` is now required on the public key ref.
   - `relayerKeyId` and `clientVerifyingShareB64u` remain present only as
     backend bridge fields and are no longer the public identity seam.

Todo:

- [ ] replace the transitional staged bootstrap payload with the real
      distributed `ecdsa-hss` request/response/finalize transport
- [x] make `clientFinalizeMessageB64u` semantically required and actually bind
      finalize output to it on the server
- [x] stop storing placeholder `relayerBackendInputB64u` envelopes and persist
      real relayer-side backend input keyed by `ecdsaThresholdKeyId`
- [x] switch sign-time relayer material loading to persisted backend input
      instead of re-deriving from `relayerKeyId`
- [x] delete the dead canonical export artifact resolver seam:
      [client/src/core/TatchiPasskey/thresholdEcdsaCanonicalExportArtifact.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/thresholdEcdsaCanonicalExportArtifact.ts)
      and related interface/API surface
- [x] make the public threshold ECDSA key ref require `ecdsaThresholdKeyId`
      and demote backend-required legacy fields from the public identity seam

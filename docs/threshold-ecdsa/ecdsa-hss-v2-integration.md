# ECDSA HSS V2 SDK Integration Plan

This plan finishes SDK and product integration for the role-local `ecdsa-hss`
boundary already implemented in the crate-local MVP.

The crate-local MVP is complete: the Rust crate derives client and relayer
shares separately, the server cannot reconstruct canonical `x`, explicit export
reconstructs client-side, and Cait-Sith signing consumes role-local additive
shares.

This plan covers the remaining SDK, WASM, server, client, persistence, export,
test, and benchmark work needed to make that boundary the active product path.

## Target State

New ECDSA HSS account creation and session bootstrap use one role-local
protocol shape:

```text
client:
  y_client -> x_client -> X_client

server:
  y_relayer -> x_relayer -> X_relayer

shared public identity:
  X = X_client + X_relayer
  ethereum_address = address(X)

explicit export:
  client receives authorized server_export_share = x_relayer
  client reconstructs x = x_client + x_relayer
  client verifies xG == X before returning privateKeyHex
```

The server persists relayer role material and public identity. The client
retains client role material. Product routes and workers never pass both root
inputs into one production function.

Existing ECDSA HSS accounts and IndexedDB records can be wiped. The integration
should remove superseded paths directly after replacement.

## Rollout Note

This change is a breaking ECDSA HSS account format change. Existing
`threshold_ecdsa_hss_key_v1` server records and old IndexedDB ECDSA HSS client
artifacts must be deleted before enabling the role-local flow. Recreated ECDSA
HSS accounts bootstrap new `threshold_ecdsa_hss_role_local` server records and
new `ecdsa-hss-role-local-client-state` browser artifacts.

Do not add migration or compatibility readers for old ECDSA HSS records. Any
old record that reaches an active product path should be rejected and the user
should re-bootstrap the ECDSA HSS account.

## Non-Goals

- No new threshold ECDSA protocol.
- No Cait-Sith/triples/presign rewrite.
- No account migration or compatibility mode.
- No additional signing round trip.
- No chain-specific ECDSA HSS key derivation. EVM chain separation stays at the
  transaction/signature-domain layer; HSS key scope stays `evm-family`.

## Source References

- Crate plan:
  `crates/ecdsa-hss/docs/plans/true-server-blindness.md`
- Crate protocol:
  `crates/ecdsa-hss/specs/protocol.md`
- Export spec:
  `crates/ecdsa-hss/specs/export.md`
- Cait-Sith integration spec:
  `crates/ecdsa-hss/specs/integration-cait-sith-backend.md`
- Current client WASM surface:
  `wasm/hss_client_signer/src/threshold_hss.rs`
- Current server WASM surface:
  `wasm/eth_signer/src/ecdsa_hss.rs`
- Current server HSS routes:
  `server/src/router/express/routes/thresholdEcdsa.ts`
  `server/src/router/cloudflare/routes/thresholdEcdsa.ts`
- Current product service:
  `server/src/core/ThresholdService/ThresholdSigningService.ts`
- Current client bootstrap flow:
  `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- Current client workers:
  `client/src/core/signingEngine/workerManager/workers/hss-client.worker.ts`
  `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- Current export flows:
  `client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
  `client/src/core/signingEngine/flows/recovery/privateKeyExportRecovery.ts`

## Current Gaps

The crate-local boundary is role-local, but product integration still has older
HSS surfaces:

- `wasm/eth_signer/src/ecdsa_hss.rs` still exposes older non-production helpers
  that parse both `y_client32_le` and `y_relayer32_le` for low-level tests and
  benchmarks.
- `wasm/hss_client_signer/src/threshold_hss.rs` now exposes only the role-local
  threshold ECDSA client bootstrap/export helpers; staged hidden-eval client
  messages are deleted from the WASM package surface.
- `/threshold-ecdsa/hss/prepare`, `/respond`, and `/finalize` are removed from
  active Express/Cloudflare routers, the client RPC module, and the server
  service surface.
- Product key stores now accept only the role-local
  `threshold_ecdsa_hss_role_local` record shape on active product paths.
- Product relayer derivation uses the fixed `evm-family` threshold PRF ECDSA
  HSS context.
- Client export reconstructs `privateKeyHex` locally from the explicit export
  artifact path.
- Product tests do not yet prove relayer key rotation, export policy failure,
  WASM surface isolation, audit redaction, and pool-hit signing behavior against
  the new role-local boundary.

## Decisions To Freeze Before Coding

These decisions should be treated as implementation constraints. If one changes,
update this plan before editing code.

### Route Shape

Use one bootstrap route:

```text
POST /threshold-ecdsa/hss/bootstrap
```

Delete the old staged hidden-eval route family after replacement:

```text
POST /threshold-ecdsa/hss/prepare
POST /threshold-ecdsa/hss/respond
POST /threshold-ecdsa/hss/finalize
```

The role-local HSS bootstrap no longer needs a three-message hidden-eval
ceremony. The client can derive `x_client` locally, send `X_client`, and receive
the public identity plus client Cait-Sith adapter material in one server
response.

Use one explicit export-share route:

```text
POST /threshold-ecdsa/hss/export/share
```

This route returns the authorized relayer export share. The client export
runtime reconstructs `privateKeyHex` locally.

### Request Identity Source

Every product route must derive the authoritative user/session identity from the
authenticated threshold/session token. Route bodies may carry identity fields for
transcript binding and diagnostics, but boundary parsers must normalize them
against authenticated claims before core logic runs.

Rules:

- `walletSessionUserId` comes from authenticated claims.
- `rpId` comes from authenticated claims.
- `subjectId` comes from the resolved wallet/account subject for this session.
- `ecdsaThresholdKeyId` is required in the request and must resolve to the same
  wallet/session subject.
- `relayerKeyId` is required in the request and must match the active relayer
  key record for this ECDSA threshold key.
- Any body-provided identity value that conflicts with claims or persisted state
  rejects at the boundary.

Core functions must receive normalized domain types, not raw route bodies.

### Active Record Version

Use one active server record version:

```ts
version: 'threshold_ecdsa_hss_role_local'
```

Use one active client record artifact kind for local role state:

```ts
artifactKind: 'ecdsa-hss-role-local-client-state'
```

Use one active explicit export artifact kind:

```ts
artifactKind: 'ecdsa-hss-secp256k1-export'
```

The old values become invalid for new code paths:

```text
threshold_ecdsa_hss_key_v1
ecdsa-hss-secp256k1-key-v1
threshold_ecdsa_hss_hidden_eval_*_v1
```

Because existing ECDSA HSS accounts can be wiped, do not add compatibility
readers for old record versions.

### Public Key Encoding

All product wire public keys use compressed SEC1:

```text
33 bytes, base64url without padding
```

All route and WASM parsers must reject:

- wrong length
- bad prefix
- non-curve point
- non-canonical encoding
- threshold public identity equal to the identity point
- `clientPublicKey33B64u` that fails canonical re-encoding equality
- `relayerPublicKey33B64u` that fails canonical re-encoding equality
- `groupPublicKey33B64u` that fails canonical re-encoding equality

Displayed EVM public keys may use hex only at UI/export display boundaries.
Core route, WASM, and persistence boundaries use base64url fixed-width bytes.

### Scalar Encoding

All scalar wires use 32-byte fixed-width base64url without padding.

Conventions:

- secret root material names: `yClient32LeB64u`, `yRelayer32LeB64u`
- additive share names: `clientShare32B64u`, `relayerShare32B64u`
- mapped Cait-Sith share names: `mappedPrivateShare32B64u`
- export share name: `serverExportShare32B64u`

The product boundary treats these as opaque fixed-width byte strings and lets
the Rust/WASM crate helpers enforce scalar validity and reduction semantics.

### Route Result Shape

Use explicit `Result`-style tagged unions for SDK/server internals:

```ts
type EcdsaHssRouteResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: EcdsaHssErrorCode; message: string; retryAfterMs?: number };
```

Core logic must switch exhaustively over result codes. Diagnostics objects must
not influence control flow.

### Error Codes

Freeze these initial error codes for tests and observability:

```text
invalid_body
unauthorized
forbidden
not_found
stale_state
relayer_key_mismatch
context_mismatch
public_key_invalid
identity_mismatch
zero_canonical_key
export_authorization_invalid
export_authorization_expired
export_nonce_replay
presign_session_invalid
presign_session_burned
pool_empty
internal
```

Error messages and logs must never include:

- root material
- additive shares
- mapped private shares
- export shares
- canonical private key bytes
- full presignature scalar material

### Relayer Key Rotation

Use the safer initial rule:

```text
relayer key id mismatch rejects
rotation requires role-local HSS re-bootstrap
```

On relayer key rotation, invalidate:

- retained relayer HSS key records for the old relayer key id
- presignature pool entries for the old relayer key id
- active presign sessions for the old relayer key id
- active signing sessions for the old relayer key id
- export authorizations for the old relayer key id
- export nonce replay keys scoped to the old relayer key id after their audit
  retention window expires

### Export Authorization Freshness

Store export nonce claims before returning any terminal export failure after the
authorization envelope is syntactically valid.

Replay scope:

```text
ecdsa-hss-export
walletSessionUserId
rpId
subjectId
ecdsaThresholdKeyId
relayerKeyId
keyHandle
thresholdSessionId
```

Replay key:

```text
exportRequestNonce32B64u
```

Freshness checks:

- issued time is within accepted clock skew
- expiry time is in the future
- nonce has not been used for the same replay key
- digest binds operation, public identity, context binding, wallet/session
  identity, client device/session, relayer key id, nonce, and expiry

### Presign Failure Semantics

Any terminal presign protocol error burns the session.

Terminal errors include:

- malformed incoming protocol message
- invalid stage transition
- protocol assertion failure
- public identity mismatch
- relayer key mismatch
- `bigR` mismatch
- expired presign session
- replay after burn

Burn means:

- delete or tombstone persisted server presign session state
- remove live in-memory WASM session
- do not persist a relayer presignature
- tell the client to discard local presign material
- require a fresh presign session for retry

`pool_empty` is not a terminal MPC failure. It must preserve the one-time MPC
authorization until either signing succeeds or the authorization expires.

### Audit And Log Redaction

Logs may include:

- `walletSessionUserId`
- `ecdsaThresholdKeyId`
- `relayerKeyId`
- request tag
- route name
- error code
- public key fingerprints
- public address
- timing fields
- pool counts

Logs must exclude:

- any `*Share32*`
- any `yClient*` or `yRelayer*`
- `privateKeyHex`
- presignature scalar material
- export share bytes
- raw authorization nonce bytes

Use stable public fingerprints for correlation:

```text
fingerprint = base64url(SHA-256(public_bytes))[0..16]
```

## Phase 1: Freeze Product Wire Shapes

Define the active SDK/server wire types before editing route behavior.

### Client bootstrap request

Client-owned fields:

```ts
type EcdsaHssClientBootstrapRequest = {
  formatVersion: 'ecdsa-hss-role-local';
  walletSessionUserId: WalletSessionUserId;
  rpId: RpId;
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: RelayerKeyId;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
};
```

Server-owned fields must be absent:

- `yRelayer32Le`
- `xRelayer32`
- relayer export share

### Server bootstrap response

Public/client-visible fields:

```ts
type EcdsaHssServerBootstrapResponse = {
  formatVersion: 'ecdsa-hss-role-local';
  walletSessionUserId: WalletSessionUserId;
  rpId: RpId;
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: RelayerKeyId;
  contextBinding32B64u: string;
  publicIdentity: {
    clientPublicKey33B64u: string;
    relayerPublicKey33B64u: string;
    groupPublicKey33B64u: string;
    ethereumAddress: string;
  };
  publicTranscriptDigest32B64u: string;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  signingRootId: SigningRootId;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  sessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  expiresAtMs: number;
  expiresAt: string;
  remainingUses: number;
};
```

Client-forbidden fields:

- client Cait-Sith mapped private share
- `xRelayer32`
- relayer export share
- canonical `x`
- `privateKeyHex`

### Server retained state

Persist only relayer-side signing material and public identity:

```ts
type EcdsaHssRelayerKeyRecord = {
  version: 'threshold_ecdsa_hss_role_local';
  walletSessionUserId: WalletSessionUserId;
  rpId: RpId;
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  keyHandle: string;
  signingRootId: SigningRootId;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: RelayerKeyId;
  contextBinding32B64u: string;
  relayerShare32B64u: string;
  relayerPublicKey33B64u: string;
  clientPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
  relayerCaitSithInput: {
    participantId: 2;
    mappedPrivateShare32B64u: string;
    verifyingShare33B64u: string;
  };
  publicTranscriptDigest32B64u: string;
  createdAtMs: number;
  updatedAtMs: number;
};
```

Forbidden persisted fields:

- `y_client`
- `x_client`
- canonical `x`
- `privateKeyHex`
- client export artifact

### Explicit export response

Server response:

```ts
type EcdsaHssExportShareResponse = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletSessionUserId: WalletSessionUserId;
  rpId: RpId;
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: RelayerKeyId;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssPublicIdentity;
  exportAuthorizationDigest32B64u: string;
  serverExportShare32B64u: string;
};
```

The client export runtime reconstructs `privateKeyHex` only after verifying:

```text
(x_client + server_export_share)G == group_public_key
address(group_public_key) == expected_address
```

### Checklist

- [x] Add product-domain TypeScript types for role-local request, response,
      retained state, and export response.
- [x] Add boundary parsers that normalize route bodies once.
- [x] Reject old hidden-eval payload kinds at the route boundary.
- [x] Add stable error-code tests for the frozen error taxonomy.
- [x] Add type fixtures with `@ts-expect-error` for forbidden branch
      combinations and forbidden fields.

## Phase 2: Split WASM Surfaces

The client and server bundles should expose separate role-specific functions.

### Client WASM

Target file:

- `wasm/hss_client_signer/src/threshold_hss.rs`

Expose only:

- derive client role share from client root material
- build client bootstrap request from `x_client` and public metadata
- validate server bootstrap response
- build client Cait-Sith input
- reconstruct explicit export key from `x_client + server_export_share`
- verify reconstructed key against persisted public identity

Remove production client access to:

- relayer derivation
- relayer export-share release
- joined-root reconstruction
- server output opening

### Server/native WASM

Target file:

- `wasm/eth_signer/src/ecdsa_hss.rs`

Expose only:

- derive relayer role share from relayer root material and client public key
- compose and validate public identity
- produce server bootstrap response
- produce retained relayer key record
- release relayer export share only after receiving a verified export
  authorization envelope

Remove production server access to:

- client root material
- client share material
- joined-root derivation
- canonical private key reconstruction
- `privateKeyHex`

### Generated package updates

After Rust/WASM edits:

- rebuild `wasm/threshold_prf/pkg` if the HSS derivation context changes
- rebuild `wasm/hss_client_signer/pkg`
- rebuild `wasm/eth_signer/pkg`
- update `.d.ts` exports
- remove old exports from JS package surfaces

### Checklist

- [x] Replace client hidden-eval functions with role-local client functions.
- [x] Replace server hidden-eval functions with role-local relayer functions.
- [x] Delete production WASM functions that accept both roots.
- [x] Add WASM export-surface tests proving client bundle lacks relayer helpers.
- [x] Add WASM export-surface tests proving server/native bundle lacks client
      root/share helpers.
- [x] Add FFI serialization tests for base64url, 32-byte scalars, 33-byte
      compressed SEC1 public keys, and scalar endianness.

## Phase 3: Server Route Integration

Targets:

- `server/src/router/express/routes/thresholdEcdsa.ts`
- `server/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
- `server/src/core/ThresholdService/ethSignerWasm.ts`
- `server/src/core/ThresholdService/thresholdPrfWasm.ts`
- `server/src/core/ThresholdService/validation.ts`
- `server/src/core/ThresholdService/stores/KeyStore.ts`

### Route behavior

Replace the staged hidden-eval flow with one role-local bootstrap route:

1. Client sends public client commitment and context binding.
2. Server authenticates session and resolves relayer root material.
3. Server derives `x_relayer` locally.
4. Server composes public identity.
5. Server stores relayer key record atomically.
6. Server returns public identity. The client builds its Cait-Sith input
   locally from retained client role material.

The route parser must reject:

- client root material
- canonical private key material
- relayer export share outside explicit export
- any chain-specific HSS derivation field, including `chainTarget`
- mismatched relayer key id
- mismatched context binding
- public key identity point
- non-canonical SEC1 public key encodings

### Bootstrap route contract

Request:

```text
POST /threshold-ecdsa/hss/bootstrap
Authorization: threshold/session auth
Body: EcdsaHssClientBootstrapRequest
```

Response:

```ts
type EcdsaHssBootstrapRouteResponse =
  | {
      ok: true;
      value: EcdsaHssServerBootstrapResponse;
    }
  | {
      ok: false;
      code: EcdsaHssErrorCode;
      message: string;
      retryAfterMs?: number;
    };
```

The route must be idempotent for the same authenticated session, request id,
context binding, client public key, ECDSA threshold key id, and relayer key id.
If the same request arrives after the relayer record is already persisted, the
server may return the existing matching public response. If any identity field
differs, reject with `stale_state` or `identity_mismatch`.

### Export-share route contract

Request:

```text
POST /threshold-ecdsa/hss/export/share
Authorization: threshold/session auth plus explicit export confirmation
Body: EcdsaHssExportShareRequest
```

Request type:

```ts
type EcdsaHssExportShareRequest = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletSessionUserId: WalletSessionUserId;
  rpId: RpId;
  subjectId: WalletSubjectId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: RelayerKeyId;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
};
```

Response:

```ts
type EcdsaHssExportShareRouteResponse =
  | {
      ok: true;
      value: EcdsaHssExportShareResponse;
    }
  | {
      ok: false;
      code: EcdsaHssErrorCode;
      message: string;
      retryAfterMs?: number;
    };
```

The server must never return `privateKeyHex` on this route.

### Persistence

Store the role-local relayer key record as the only active product record shape.

Rules:

- relayer key id mismatch rejects
- relayer key rotation requires re-bootstrap
- stale presignatures and signing sessions for the old relayer key become invalid
- export nonce storage is keyed by wallet user, ECDSA key id, relayer key id,
  export nonce, and authorization digest
- the key-store parser, filtered uniqueness index, and insert-conflict query use
  only `threshold_ecdsa_hss_role_local` for active ECDSA HSS records

### Checklist

- [x] Add role-local HSS bootstrap service method.
- [x] Mint role-local bootstrap threshold session and wallet signing-session
      budget fields.
- [x] Add role-local HSS export-share service method.
- [x] Add `POST /threshold-ecdsa/hss/bootstrap` to Express and Cloudflare
      route definitions.
- [x] Add `POST /threshold-ecdsa/hss/export/share` to Express and Cloudflare
      route definitions.
- [x] Delete `/threshold-ecdsa/hss/prepare` from active Express/Cloudflare
      routers.
- [x] Delete `/threshold-ecdsa/hss/respond` from active Express/Cloudflare
      routers.
- [x] Delete `/threshold-ecdsa/hss/finalize` from active Express/Cloudflare
      routers.
- [x] Update Express and Cloudflare route parity.
- [x] Add role-local key-store persistence path for bootstrap records.
- [x] Rewire signing-root resolver unit coverage off staged
      `ecdsaHss.prepare` and onto role-local bootstrap while preserving
      resolver and share assertions.
- [x] Update key-store validation to accept only
      `threshold_ecdsa_hss_role_local`.
- [x] Resolve ECDSA key identity inventory from role-local records only.
- [x] Point the Postgres shared-identity helper index at
      `threshold_ecdsa_hss_role_local`.
- [x] Delete hidden-eval transport parsers once no route imports them.
- [x] Add product route tests for forbidden fields, malformed public keys,
      relayer key mismatch, and zero canonical key rejection.
- [x] Add export authorization digest verification and nonce replay storage
      before enabling explicit key export outside development.
- [x] Remove `chainTarget` from threshold PRF ECDSA HSS relayer derivation and
      keep product HSS context fixed to `evm-family`.

## Phase 4: Client SDK Integration

Targets:

- `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `client/src/core/signingEngine/workerManager/workers/hss-client.worker.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`
- `client/src/core/signingEngine/interfaces/signing.ts`
- `client/src/core/signingEngine/session/persistence/records.ts`

### Client behavior

1. Derive and retain `x_client` locally.
2. Send only public client commitment and transcript metadata to the server.
3. Validate server public identity and context binding.
4. Build client Cait-Sith input locally from retained client role material.
5. Store client role signing material in the active session record.
6. Feed presign/sign with local client Cait-Sith input and server public
   identity.

Client state must include:

- `ecdsaThresholdKeyId`
- `contextBinding32`
- `x_client`
- `X_client`
- `X_relayer`
- `X`
- `ethereumAddress`
- `relayerKeyId`
- client Cait-Sith mapped share

Client state must exclude:

- `x_relayer`
- relayer export share outside explicit export
- relayer root material

### Client state contract

Represent client role-local state as a discriminated union:

```ts
type EcdsaHssClientState =
  | {
      kind: 'role_local_ready';
      artifactKind: 'ecdsa-hss-role-local-client-state';
      walletSessionUserId: WalletSessionUserId;
      rpId: RpId;
      subjectId: WalletSubjectId;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      relayerKeyId: RelayerKeyId;
      contextBinding32B64u: string;
      clientShare32B64u: string;
      clientPublicKey33B64u: string;
      relayerPublicKey33B64u: string;
      groupPublicKey33B64u: string;
      ethereumAddress: string;
      clientCaitSithInput: {
        participantId: 1;
        mappedPrivateShare32B64u: string;
        verifyingShare33B64u: string;
      };
      createdAtMs: number;
      updatedAtMs: number;
    }
  | {
      kind: 'explicit_export_ready';
      artifactKind: 'ecdsa-hss-secp256k1-export';
      walletSessionUserId: WalletSessionUserId;
      rpId: RpId;
      subjectId: WalletSubjectId;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      relayerKeyId: RelayerKeyId;
      ethereumAddress: string;
      publicKeyHex: string;
      privateKeyHex: string;
      exportedAtMs: number;
    };
```

Core signing functions must accept only `kind: 'role_local_ready'`. Export
display and recovery flows may accept only `kind: 'explicit_export_ready'`.

### Checklist

- [x] Add typed SDK relayer client methods for role-local bootstrap and
      export-share routes.
- [x] Expose role-local client bootstrap material from `hss_client_signer`
      WASM.
- [x] Add worker request/response plumbing and typed SDK helper for role-local
      client bootstrap material.
- [x] Route concrete-key threshold-session bootstrap through role-local client
      material and `/threshold-ecdsa/hss/bootstrap`.
- [x] Persist role-local client signing state and map the active signing share
      to the client Cait-Sith input.
- [x] Replace client hidden-eval bootstrap worker calls. Passkey
      `bootstrapSession` and Email OTP worker bootstrap now call the role-local
      route directly and fail closed when concrete role-local identity is
      missing.
- [x] Finish Email OTP role-local bootstrap coverage by moving the existing-key
      path after concrete role-local key identity is available at that boundary.
- [x] Route Email OTP exact-session bootstrap through role-local client material
      and `/threshold-ecdsa/hss/bootstrap` when the auth JWT carries
      `relayerKeyId`.
- [x] Add a first-bootstrap role-local authorization route or extend
      `/threshold-ecdsa/hss/bootstrap` to accept the same app-session /
      Email-OTP authorization envelope currently handled by prepare.
      `/threshold-ecdsa/hss/bootstrap` now accepts registration-time Email OTP
      role-local bootstrap when the request carries a client-root proof. The
      route verifies deterministic `ecdsaThresholdKeyId`, deterministic
      `relayerKeyId`, an active Email OTP enrollment, and a recoverable
      secp256k1 signature over the role-local bootstrap identity against the
      enrolled client-root public key.
- [x] Update Email OTP registration bootstrap to use the same client role-local
      path when `runtimePolicyScope` is present. The worker derives
      `signingRootId`, `signingRootVersion`, deterministic `ecdsaThresholdKeyId`,
      and deterministic `relayerKeyId`, generates role-local client material,
      signs the first-bootstrap proof with the Email OTP client root share, then
      calls `/threshold-ecdsa/hss/bootstrap`.
- [x] Move Email OTP multi-target existing-key bootstrap onto the same
      role-local path after the first target returns canonical role-local key
      identity. The worker carries `ecdsaThresholdKeyId`, `signingRootId`,
      `signingRootVersion`, and `relayerKeyId` forward, then signs the same
      first-bootstrap proof for subsequent targets.
- [x] Update Email OTP existing-key bootstrap to use role-local bootstrap once
      that call path carries concrete `ecdsaThresholdKeyId`, `signingRootId`,
      `signingRootVersion`, and `relayerKeyId`. Runtime-scoped handle-only
      callers now derive that identity before entering the worker and verify the
      derived key handle matches the provided `keyHandle`; requests without
      runtime scope remain on the fallback path because `keyHandle` alone is too
      loose for the new route boundary.
- [x] Update passkey exact-session/bootstrap-auth flows to use the same client
      role-local path when route auth carries `relayerKeyId`. The shared
      `bootstrapSession` role-local branch builds client material through
      `hss_client_signer`, calls `/threshold-ecdsa/hss/bootstrap`, and stores
      `ecdsaHssRoleLocalClientState`.
- [x] Specify passkey first-bootstrap role-local authorization before removing
      its hidden-eval fallback. Passkey first-bootstrap should use WebAuthn or
      registration-continuation authorization for key creation, plus deterministic
      role-local identity checks. There is no pre-existing ECDSA client-root
      verifier for a brand-new passkey key, so the security property is
      authorization-to-create rather than verification against an enrolled ECDSA
      root.
- [x] Implement passkey first-bootstrap role-local authorization using the spec
      below. The shared `bootstrapSession` path now computes deterministic
      role-local key ids before WebAuthn, uses the passkey authorization digest
      as the assertion challenge, and sends
      `passkeyFirstBootstrapAuthorization` to `/threshold-ecdsa/hss/bootstrap`.
- [x] Add route-level passkey first-bootstrap coverage for valid WebAuthn
      authorization, runtime-scope mismatch rejection, and failed WebAuthn
      rejection before relayer bootstrap persistence.
- [x] Remove passkey first-bootstrap hidden-eval fallback now that the route
      authorization path has focused coverage. Fresh registration bootstrap now
      rejects without `runtimePolicyScope` or `runtimeScopeBootstrap` instead of
      falling through to prepare/respond/finalize.
- [x] Remove hidden-eval fallback from the shared passkey `bootstrapSession`
      exact-session path. Exact-session bootstrap now also fails closed unless
      it has concrete role-local key identity plus `relayerKeyId`.
- [x] Remove hidden-eval fallback from the Email OTP bootstrap worker. Missing
      exact-session `relayerKeyId`, missing existing-key role-local identity, or
      missing runtime scope now rejects instead of falling through to
      prepare/respond/finalize.
- [x] Remove IndexedDB readers for superseded ECDSA HSS records. The ECDSA
      session record normalizer now rejects persisted records without
      `ecdsaHssRoleLocalClientState`, and new writes require role-local state
      from the bootstrap result. The TypeScript record field remains optional
      temporarily for legacy test fixtures that construct records directly.
- [x] Remove old hidden-eval transport helper imports from active passkey and
      Email OTP bootstrap callers.
- [x] Remove old hidden-eval HSS client worker request/response surfaces from
      client worker maps and `hssClientSignerWasm` wrappers.
- [x] Remove old hidden-eval RPC helper surfaces after server route removal.
- [x] Add client tests for local-only `x_client`, response validation, and
      relayer-key mismatch rejection.
- [x] Add client guard coverage for Email OTP exact-session role-local
      bootstrap before hidden-eval fallback.

### Passkey First-Bootstrap Role-Local Spec

Passkey first-bootstrap differs from Email OTP first-bootstrap. Email OTP has an
enrolled ECDSA client-root public key, so `/threshold-ecdsa/hss/bootstrap` can
verify a client-root proof against existing enrollment state. A brand-new
passkey ECDSA key has no prior ECDSA root verifier. The route must therefore
authorize creation with the same passkey/registration-continuation policy used
by the prepare/finalize path, then bind that authorization to the exact
role-local request.

Required route inputs for passkey first-bootstrap:

```ts
type EcdsaHssPasskeyFirstBootstrapAuthorization = {
  kind: 'passkey_first_bootstrap';
  webauthn_authentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: RuntimePolicyScope;
  runtimeEnvironmentId?: string;
};
```

Authorization rules:

- Threshold-session authorization remains the preferred path. If the bearer
  token parses as a threshold ECDSA session, keep the existing
  `validateEcdsaHssSessionIdentity` behavior.
- Email OTP first-bootstrap keeps `clientRootProof` and active enrollment
  verification.
- Passkey first-bootstrap is allowed only for deterministic key creation:
  `ecdsaThresholdKeyId` must equal
  `computeEcdsaHssRoleLocalThresholdKeyId(walletSessionUserId, rpId, subjectId,
  signingRootId, signingRootVersion)`, and `relayerKeyId` must equal
  `computeEcdsaHssRoleLocalRelayerKeyId(walletSessionUserId, rpId)`.
- The request must carry either a valid registration-continuation bearer whose
  runtime scope and wallet policy match the requested role-local identity, or a
  WebAuthn authentication assertion for `walletSessionUserId` and `rpId`.
- WebAuthn first-bootstrap must resolve a runtime policy scope from either
  `runtimePolicyScope` or `runtimeEnvironmentId` plus publishable-key auth, then
  reject if the resolved `signingRootId` or `signingRootVersion` differs from
  the role-local request.
- WebAuthn challenge binding must be explicit and non-circular. A fresh passkey
  PRF root is obtained from the WebAuthn assertion, so the WebAuthn challenge
  cannot include `clientPublicKey33B64u` or `contextBinding32B64u`, which are
  derived from that PRF output. The challenge must instead be a deterministic
  digest over the pre-client-root request identity:
  `walletSessionUserId`, `rpId`, `subjectId`, `ecdsaThresholdKeyId`,
  `signingRootId`, `signingRootVersion`, `keyScope`, `relayerKeyId`,
  `requestId`, `sessionId`, `walletSigningSessionId`, `ttlMs`,
  `remainingUses`, and `participantIds`.
- After WebAuthn returns the PRF root, the client builds
  `clientPublicKey33B64u` and `contextBinding32B64u` locally. The server
  validates `contextBinding32B64u` by recomputing the role-local HSS context in
  `ecdsaHssRoleLocalBootstrap`.
- The server must verify the WebAuthn assertion before calling
  `ecdsaHssRoleLocalBootstrap`. It must reject missing or failed verification
  with `unauthorized` and must not persist relayer role-local state.
- The passkey path does not need an Email-OTP-style client-root proof. For a new
  key, the passkey assertion authorizes creation of whatever client role-local
  share the authenticated client presents. Subsequent sessions are protected by
  the persisted key handle, relayer key id, client verifying share, and
  threshold-session auth.

Client implementation steps:

- For passkey fresh first-bootstrap with `runtimePolicyScope`, compute
  deterministic `ecdsaThresholdKeyId`, `signingRootId`, `signingRootVersion`,
  and `relayerKeyId` before prompting WebAuthn.
- Build role-local client material locally with `hss_client_signer`.
- Compute the passkey first-bootstrap authorization digest from the pre-client
  request identity and use it as the WebAuthn challenge for the passkey
  assertion.
- Send the role-local bootstrap request directly to
  `/threshold-ecdsa/hss/bootstrap` with the WebAuthn assertion attached as
  `passkeyFirstBootstrapAuthorization`.
- Preserve the existing hidden-eval fallback until this route-level WebAuthn
  verification has targeted tests for success, runtime-scope mismatch, and
  failed assertion rejection.

## Phase 5: Sign And Presign Integration

Targets:

- `client/src/core/signingEngine/threshold/ecdsa/presignPool.ts`
- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `crates/signer-core/src/threshold_ecdsa.rs`

The Cait-Sith presign/sign runtime should keep its current protocol shape. The
integration work is to source its role material from the new HSS records.

### Required behavior

- presign init loads relayer mapped share from the role-local key record
- client presign uses retained client mapped share
- sign init binds the request to `walletSessionUserId`, `ecdsaThresholdKeyId`,
  relayer key id, public identity, and participant ids
- relayer presignatures are keyed internally by key handle, so two wallets that
  share a relayer key id cannot consume each other's presignature material
- relayer key id mismatch rejects before any MPC message is accepted
- failed presign sessions burn server-side state
- failed client presign state is deleted locally
- `pool_empty` preserves the one-time MPC authorization until a presignature is
  available or the authorization expires by restoring the MPC session when
  `sign/init` cannot reserve a matching presignature

### Checklist

- [x] Re-key presign init to the role-local HSS key record.
- [x] Re-key sign init/finalize to the role-local HSS key record.
- [x] Add product presign tests for relayer key mismatch.
- [x] Add product presign tests for cross-user/key misuse.
- [x] Add invalid protocol message regression proving the server deletes or
      burns that presign session.
- [x] Fix the `pool_empty` authorization-consumption issue before relying on
      retry-heavy refill behavior.
- [x] Add pool-hit and pool-miss product benchmarks.

## Phase 6: Explicit Export Integration

Targets:

- `client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
- `client/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts`
- `client/src/core/signingEngine/flows/recovery/privateKeyExportRecovery.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `server/src/core/ThresholdService/ThresholdSigningService.ts`

### Server behavior

The server releases only `serverExportShare32B64u` after:

- authenticated user/session check
- export policy check
- fresh export authorization
- relayer key id match
- public identity match
- nonce replay guard insert before digest/policy failure returns

The server response must exclude:

- `privateKeyHex`
- canonical `x`
- client share/root material

### Confirmation digest

Product code must define the confirmation digest before wiring the export-share
route. The product digest is the source for the crate
`confirmation_digest32` field in `ExplicitExportAuthorizationV1`.

Digest frame:

```text
base64url(SHA-256(alphabetizeStringify({
  version: "ecdsa-hss:role-local:product-export-confirmation:v1",
  walletSessionUserId,
  rpId,
  subjectId,
  ecdsaThresholdKeyId,
  relayerKeyId,
  contextBinding32B64u,
  publicIdentity: {
    clientPublicKey33B64u,
    relayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress
  },
  clientDeviceId,
  clientSessionId,
  exportRequestNonce32B64u,
  issuedAtUnixMs,
  expiresAtUnixMs
})))
```

The authorization digest must bind the confirmation digest, the explicit export
operation, the same public identity, relayer key id, nonce, issued time, expiry,
authenticated wallet/session identity, key handle, signing root identity, threshold
session id, wallet-signing session id, threshold session expiry, and participant
ids, using the same `alphabetizeStringify` + SHA-256 + base64url encoding.

### Client behavior

The client export runtime:

1. Receives `serverExportShare32B64u`.
2. Reconstructs canonical scalar from local `x_client`.
3. Verifies public key and Ethereum address.
4. Returns `privateKeyHex` only inside the explicit export artifact path.

### Checklist

- [x] Add server-side export freshness, digest, session-claim binding, and nonce replay enforcement.
- [x] Replace passkey export route response parsing with `serverExportShare32B64u`.
- [x] Move passkey `privateKeyHex` creation to the client HSS export runtime.
- [x] Update passkey confirmation export flow.
- [x] Update Email OTP recovery/export flow.
- [x] Add export policy failure tests.
- [x] Add nonce replay tests at the product persistence boundary.
- [x] Add audit/log redaction tests for export failures.

## Phase 7: Cleanup

After the new product flow is active:

- [x] Delete unused client hidden-eval ECDSA HSS transport:
      `client/src/core/signingEngine/threshold/ecdsa/hssTransport.ts`
- [x] Delete server hidden-eval ECDSA HSS transport after lower-level service
      helpers are removed:
      `server/src/core/ThresholdService/ecdsaHssTransport.ts`
- [x] Delete superseded hidden-eval WASM exports and regenerate package
      declarations.
- [x] Delete server-side compatibility paths for old HSS records.
- [x] Remove old integrated-key fallback from ECDSA presign/sign authorization.
- [x] Delete the old client-root ECDSA HSS bootstrap/export helpers from
      `ThresholdSigningService`.
- [x] Remove AuthService callers for the deleted client-root ECDSA HSS bootstrap
      helper.
- [x] Delete IndexedDB compatibility readers for old ECDSA HSS records.
- [x] Delete tests whose only assertion is old hidden-eval compatibility.
- [x] Remove stale Express/Cloudflare router tests and client authorization
      bootstrap tests that asserted the deleted staged hidden-eval ECDSA HSS
      prepare route.
- [x] Delete the hidden-eval transport shape unit test whose only purpose was
      compatibility coverage for the removed staged envelope protocol.
- [x] Rewire the threshold ECDSA signature relayer harness from staged
      prepare/respond/finalize bootstrap to role-local bootstrap, export/share,
      and `keyHandle` authorize/presign selection.
- [x] Remove deleted threshold ECDSA HSS staged route ids from route-definition
      policy tests.
- [x] Replace the old hidden-eval ECDSA HSS bootstrap policy unit suite with
      focused role-local bootstrap policy coverage for deterministic
      `evm-family` identity, stable-field key separation, no export-material
      leakage, and `keyHandle` authorization.
- [x] Update docs to state existing ECDSA HSS accounts must be recreated.
- [x] Remove active route definitions for `/threshold-ecdsa/hss/prepare`,
      `/threshold-ecdsa/hss/respond`, and `/threshold-ecdsa/hss/finalize`.
- [x] Remove the staged ECDSA HSS `hss.prepare/respond/finalize` surface from
      the public threshold scheme module registry.
- [x] Remove the internal server `ecdsaHss.prepare/respond/finalize` service
      surface and the typecheck fixtures that only covered the deleted staged
      prepare request.

## Pre-Implementation Check Results

These checks were completed before the first implementation patch. The findings
below are implementation constraints.

### Route Callers

Current product callers of the three staged HSS routes are:

- `client/src/core/rpcClients/relayer/thresholdEcdsa.ts`
- `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`

Current server route/service surfaces are:

- `server/src/router/routeDefinitions.ts`
- `server/src/router/express/routes/thresholdEcdsa.ts`
- `server/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
- `server/src/core/ThresholdService/ethSignerWasm.ts`

Documentation references that must be updated or deleted during cleanup:

- `docs/auth-gating-routes.md`
- `docs/threshold-ecdsa/presigning-pool.md`
- `docs/cloudflare-signing-worker-self-host.md`
- `docs/refactor-36.md`
- `docs/refactor-37.md`

### Route Inventory

`server/src/router/routeDefinitions.ts` is the active route inventory. There is
no separate generator requiring deletion tombstones. Replace these route ids:

```text
threshold_ecdsa_hss_prepare
threshold_ecdsa_hss_respond
threshold_ecdsa_hss_finalize
```

with:

```text
threshold_ecdsa_hss_bootstrap
threshold_ecdsa_hss_export_share
```

Then update Express and Cloudflare route implementations directly.

### Key Store And Indexes

`server/src/core/ThresholdService/stores/KeyStore.ts` stores ECDSA HSS records in
`threshold_ecdsa_keys`. Existing indexed columns include:

- `key_handle`
- `threshold_key_id`
- `signing_root_id`
- `signing_root_version`
- `owner_address`
- `public_key_b64u`

Relevant uniqueness constraints:

- `(namespace, key_handle)`
- `(namespace, threshold_key_id, signing_root_id, signing_root_version)`

The shared identity filtered index and insert-conflict query currently filter on:

```text
record_json->>'version' = 'threshold_ecdsa_hss_key_v1'
```

Implementation must update those filters to the new active version:

```text
threshold_ecdsa_hss_role_local
```

The parser in `server/src/core/ThresholdService/validation.ts` and the record
type in `server/src/core/types.ts` still accept old fields such as
`relayerRootShare32B64u` and `relayerBackendInputB64u`. Replace the active parser
and type with the role-local record. Existing accounts can be wiped, so active
read paths should reject old versions.

The product role-local record type includes a required `keyHandle` because the
current Postgres table enforces `key_handle NOT NULL` and keeps a unique
`(namespace, key_handle)` index.

### Identity Normalization

Current Express and Cloudflare ECDSA HSS prepare routes resolve identity through
session claims, runtime policy claims, and Email OTP enrollment claims. Both
route files duplicate the same identity work.

Implementation should extract or share the normalization path used by:

- threshold Ed25519 session claims
- threshold ECDSA session claims
- registration continuation claims
- `resolveEcdsaRuntimePolicyScopeFromClaims`
- `applyEcdsaRuntimePolicyScope`
- `resolveEmailOtpEnrollmentClaimsForThresholdEcdsa`

The new bootstrap and export-share route parsers should receive raw route
bodies, resolve authenticated identity once, reject conflicts with body fields,
and pass normalized domain types into core service methods.

### Threshold PRF Context

The current product relayer derivation still passes a chain target:

- `server/src/core/ThresholdService/thresholdPrfWasm.ts`
- `wasm/threshold_prf/src/lib.rs`

The role-local crate context is fixed to `evm-family`. Implementation must
remove `chainTarget` from the ECDSA HSS relayer PRF path or the product share
derivation can drift from the crate/formal boundary. Route bodies should reject
chain-specific HSS derivation fields.

### Presign And Sign Authorization

Presign init already rejects relayer key mismatch before creating WASM presign
state. Presign step also checks user, rp, participant ids, and relayer key id
against persisted presign session state before accepting protocol messages.

Sign init currently consumes the one-time MPC session with
`takeMpcSession(mpcSessionId)` before reserving a presignature. If the presign
pool is empty, the route returns `pool_empty` after consuming authorization.

Implementation must fix this ordering before relying on retry-heavy signing:

- reserve or confirm an available presignature before consuming the MPC session
- or add a transactional claim/peek path that preserves the authorization on
  `pool_empty`

### Export Confirmation

The Rust crate defines `ExplicitExportAuthorizationV1` with:

- `authorization_digest32`
- `confirmation_digest32`
- `export_request_nonce32`
- `issued_at_unix_ms`
- `expires_at_unix_ms`

The product route layer does not yet produce a stable ECDSA HSS confirmation
digest. Current product export still expects server-side `privateKeyHex` from
old finalize/export paths. Define the product confirmation digest in Phase 6
before wiring `/threshold-ecdsa/hss/export/share`.

### Logging And Redaction

The generic observability redactor denies broad keys such as `authorization`,
`token`, `secret`, `password`, `api_key`, `apikey`, `private_key`, `cookie`, and
`signature`. That is insufficient for ECDSA HSS because common field names such
as `clientShare32B64u`, `relayerShare32B64u`,
`serverExportShare32B64u`, `relayerRootShare32B64u`,
`relayerBackendInputB64u`, `mappedPrivateShare32B64u`, and `privateKeyHex` can
avoid those exact patterns.

Implementation must add an ECDSA HSS route/service logging helper that emits an
allowlisted log object. The helper may include ids, route names, error codes,
public addresses, public key fingerprints, timing, and pool counts. It must
drop raw route bodies and secret-bearing fields by construction.

### WASM Rebuild Commands

Root command:

```sh
pnpm build:wasm
```

SDK command:

```sh
pnpm -C sdk build:wasm
```

The SDK build script rebuilds all relevant packages in parallel:

- `wasm/hss_client_signer/pkg`
- `wasm/eth_signer/pkg`
- `wasm/threshold_prf/pkg`
- other SDK WASM packages

Focused benchmark rebuild for the ECDSA HSS WASM benchmark:

```sh
pnpm benchmark:ecdsa-hss:wasm
```

That benchmark currently rebuilds `wasm/eth_signer/pkg` and runs
`benchmarks/ecdsa-hss-wasm/src/runner.mjs`. Add or update the benchmark runner
when role-local client bootstrap and threshold PRF context changes need
Node-hosted measurements.

## Phase 8: Tests And Verification

### Required unit and integration tests

- [x] Type-level tests reject forbidden role-state combinations.
- [x] Server route rejects client root/share/canonical private key fields.
- [x] Client parser rejects relayer secret fields in non-export response.
- [x] Server key record parser rejects old hidden-eval record shape.
- [x] Route-boundary public key validation rejects bad length and bad prefix.
- [x] Service-level public key validation maps invalid compressed client points
      to `public_key_invalid`.
- [x] Service-level public key validation covers non-canonical encoding and
      identity threshold sum behavior.
- [x] Export authorization rejects mismatched wallet, key id, relayer key id,
      public identity, context binding, digest, expiry, and nonce replay.
- [x] Relayer key rotation invalidates bootstrap, presign, signing, and export
      attempts under the old key id.
- [x] Presign malformed-message path burns the session.
- [x] Cross-user blast-radius test proves user A cannot run MPC against user B's
      relayer share.

### Formal and crate gates

Run after product integration touches crate or formal boundary files:

```sh
cargo test --manifest-path crates/ecdsa-hss/Cargo.toml
cargo check --manifest-path crates/ecdsa-hss/Cargo.toml --all-targets
just ecdsa-hss-fv
```

### TypeScript gates

Use the cheapest focused checks first:

```sh
pnpm test -- thresholdEcdsa
pnpm test -- ecdsa-hss
pnpm typecheck
```

Run broader suites only after route, persistence, or worker changes touch shared
signing behavior.

## Phase 9: Benchmarks

Native crate-local baseline is already measured:

| Path | Current |
| --- | ---: |
| Context binding | `~644 ns` |
| Client share | `~32.39 us` |
| Relayer share + identity | `~60.30 us` |
| Bootstrap adapter | `~221.66 us` |
| First presign roundtrip | `~38.38 ms` |
| Full sign bridge | `~38.59 ms` |
| Explicit export | `~291.92 us` |

Product integration measurements:

- [x] Node-hosted WASM role-local client bootstrap benchmark.
- [x] Node-hosted WASM role-local server bootstrap benchmark.
- [x] Browser client bootstrap benchmark.
- [x] Product serialized request/response byte-size measurement.
- [x] Product retained client/server state byte-size measurement.
- [x] Pool-hit signing benchmark.
- [x] Pool-miss signing benchmark.
- [x] `pool_empty` retry benchmark.
- [x] Explicit export product benchmark.

Performance acceptance:

- HSS bootstrap and export stay sub-millisecond in native Rust.
- Product signing does not add a network round trip.
- Pool-hit signing remains dominated by existing sign-finalization and transport
  overhead.
- Cold signing remains dominated by Cait-Sith presign/triples work.
- Any Cait-Sith presign/sign regression blocks release unless traced to an
  intentional backend change.

Focused product benchmark smoke runs:

```sh
node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario warm_sign_pool_hit --iterations 1
node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 1
node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario pool_empty_retry --iterations 1
node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario explicit_export_product --iterations 1
pnpm benchmark:ecdsa-hss:wasm
```

Latest product smoke values:

| Scenario | Iterations | Mean |
| --- | ---: | ---: |
| `cold_first_sign_no_pool` | 2 | `165 ms` |
| `warm_sign_pool_hit` | 2 | `8.5 ms` |
| `pool_empty_retry` | 2 | `2.5 ms` |
| `explicit_export_product` | 2 | `4.5 ms` |

Latest role-local WASM values:

| Path | Median | Mean |
| --- | ---: | ---: |
| `role_local_client_bootstrap_wasm` | `0.143 ms` | `0.152 ms` |
| `role_local_server_bootstrap_wasm` | `0.196 ms` | `0.203 ms` |
| `role_local_full_bootstrap_wasm` | `0.321 ms` | `0.355 ms` |
| `role_local_export_artifact_wasm` | `0.216 ms` | `0.221 ms` |
| `browser_role_local_client_bootstrap_wasm` | `0.1 ms` | `0.158 ms` |

Latest serialized size values:

| Payload | Bytes |
| --- | ---: |
| `client_bootstrap_request_json` | `510` |
| `client_bootstrap_response_json` | `619` |
| `server_bootstrap_request_json` | `561` |
| `server_bootstrap_response_json` | `969` |
| `client_export_artifact_request_json` | `955` |
| `role_local_client_state_json` | `440` |
| `role_local_server_record_json` | `490` |

Latest benchmark artifacts:

- Product: `benchmarks/threshold-ecdsa-presign/out/20260520-132907Z/summary.md`
- WASM: `benchmarks/ecdsa-hss-wasm/out/2026-05-20T13-37-05-119Z/summary.md`

## Implementation Order

1. Freeze TypeScript product wire types and parsers.
2. Split WASM client/server surfaces.
3. Replace server route behavior and key persistence.
4. Replace client bootstrap and local session persistence.
5. Re-key presign/sign to role-local records.
6. Replace explicit export flow.
7. Delete superseded hidden-eval transport and old record readers.
8. Add product security tests.
9. Add WASM/product benchmarks.
10. Update docs and release notes.

## Done Criteria

- [x] New ECDSA HSS bootstrap never sends client root/share material to server.
- [x] Server cannot reconstruct canonical `x` through any production path.
- [x] Client cannot receive `x_relayer` during non-export flows.
- [x] Explicit export returns `privateKeyHex` only from client export runtime.
- [x] Presign/sign uses role-local HSS records for both client and relayer.
- [x] Relayer key mismatch rejects bootstrap, presign, signing, and export.
- [x] Active old hidden-eval ECDSA HSS route and client RPC paths are deleted.
- [x] Lower-level old hidden-eval ECDSA HSS service/WASM helpers are deleted.
- [x] Existing ECDSA HSS accounts are documented as wipe/recreate.
- [x] Product tests cover forbidden fields, export policy, relayer rotation,
      malicious presign failure, and cross-user blast radius.
- [x] Native and WASM benchmark results are recorded in benchmark artifacts and docs.

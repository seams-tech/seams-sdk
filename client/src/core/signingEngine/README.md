# Signing Architecture (`client/src/core/signingEngine`)

This folder is the signing runtime for NEAR + Tempo/EVM flows.

## Top-Level Roles

- `api/`
  - Internal composition/surface wiring used by `SigningEngine`.
  - Coordinates session policy, worker context, SecureConfirm, and engine dispatch.
- `interfaces/`
  - Shared signing contracts (`SigningIntent`, `SignRequest`, `Signer`) and runtime dependency interfaces.
- `orchestration/`
  - Generic runner (`executeSigningIntent`) and activation/deployment orchestration.
- `signers/algorithms/`
  - Algorithm-specific signing implementations (`ed25519`, `secp256k1`, `webauthnP256`).
- `signers/wasm/`
  - WASM-backed chain signing wrappers (`ethSignerWasm`, `tempoSignerWasm`).
- `chainAdaptors/`
  - Chain-specific intent builders and handlers (NEAR, Tempo, EVM helpers).
- `secureConfirm/`
  - User confirmation flow + WebAuthn credential collection.
- `workers/`
  - Worker transports:
  - `signerWorkerManager`: unified worker architecture layer.
  - `signerWorkerManager/backends/nearWorkerBackend`: NEAR signer worker transport.
  - `signerWorkerManager/backends/multichainWorkerBackend`: EVM/Tempo worker transport.
  - `signerWorkerManager/nearKeyOps`: NEAR-only key operations invoked via `SignerWorkerManager.nearKeyOps`.
- `threshold/`
  - Threshold session, authorization, and signing workflows.
- `signers/webauthn/`
  - Passkey prompt and credential serialization helpers.

## Module Call Graph (Compact)

### 1) High-level map

```mermaid
flowchart LR
  TP["TatchiPasskey"] --> SE["SigningEngine"]
  SE --> ORCH["orchestration/executeSigningIntent"]
  ORCH --> ENG["signers/algorithms/*"]
  ENG --> CHAINS["chainAdaptors/*"]
  SE --> SC["secureConfirm/*"]
  CHAINS --> WORKERS["workers/*"]
```

### 2) Signing execution pipeline

```mermaid
flowchart LR
  ADAPTER["Chain Adapter"] --> INTENT["SigningIntent"]
  INTENT --> EXEC["executeSigningIntent"]
  EXEC --> RESOLVE["resolveSignInput(req)"]
  RESOLVE --> ENGINE["engine.sign(req, keyRef)"]
  ENGINE --> FINALIZE["intent.finalize(signatures)"]
```

### 3) Worker transports

```mermaid
flowchart LR
  NH["NEAR handlers"] --> SWM["SignerWorkerManager"]
  SE["SigningEngine (NEAR key ops)"] --> SWM
  SWM --> NB["NearSignerWorkerTransport"]
  SWM --> NKO["nearKeyOps service"]
  NB --> NSW["near-signer.worker"]
  NKO --> NB

  WASM["ethSignerWasm / tempoSignerWasm"] --> EX["executeSignerWorkerOperation"]
  EX --> SWM
  EX --> MB
  MB --> EWK["eth-signer.worker"]
  MB --> TWK["tempo-signer.worker"]
```

## Core Flows

### 1) NEAR Signing (`transactionsWithActions`, `delegate`, `NEP-413`)

1. `SigningEngine` creates a NEAR ed25519 sign request and calls `executeSigningIntent`.
2. `NearEd25519Engine` routes by request kind to NEAR handlers.
3. Handler performs:
   - input normalization (`NearAdapter` for transactions),
   - SecureConfirm handshake (`SecureConfirmWorkerManager.confirmAndPrepareSigningSession`),
   - signer worker call via `ctx.requestWorkerOperation(...)`.
4. `SignerWorkerManager.requestWorkerOperation` sends request to `near-signer.worker`.
5. Worker response returns signed payload back through handler -> engine -> `finalize`.

### 2) Tempo Signing (`eip1559` / `tempoTransaction`)

1. `SigningEngine.signTempo` imports:
   - `signTempoWithSecureConfirm`,
   - `Secp256k1Engine`,
   - `WebAuthnP256Engine`.
2. `TempoAdapter.buildIntent` computes signing digest/challenge using:
   - `ethSignerWasm` (EIP-1559 hash/encoding),
   - `tempoSignerWasm` (Tempo sender hash/encoding).
3. `signTempoWithSecureConfirm` runs SecureConfirm once for intent approval.
4. `executeSigningIntent` dispatches to:
   - `secp256k1` engine (local or threshold ECDSA path), or
   - `webauthnP256` engine (serialized credential or browser WebAuthn call).
5. Adapter `finalize` returns encoded raw tx hex.

### 3) secp256k1 Threshold Path (inside `Secp256k1Engine`)

1. Validate cached/session JWT and threshold key ref.
2. Authorize digest with relayer (`thresholdEcdsaAuthorize`).
3. Dispense PRF.first from SecureConfirm session cache.
4. Derive client share in `ethSignerWasm`.
5. Run distributed signing coordination (`thresholdEcdsaCoordinator`).
6. Return 65-byte recoverable secp256k1 signature.

### 4) Worker RPC Path (`ethSigner` / `tempoSigner`)

1. Chain wasm wrapper (`ethSignerWasm` or `tempoSignerWasm`) calls `executeSignerWorkerOperation(...)`.
2. Helper dispatches via `SignerWorkerManager.requestWorkerOperation({ kind, request })` (runtime context is required).
3. `MultichainSignerWorkerTransport` lazily creates a dedicated module worker by kind.
4. Request/response is correlated by message `id`.
5. Returned `ArrayBuffer` is decoded to `Uint8Array` in caller.

## Practical Rule of Thumb

- `SigningEngine` owns product-level orchestration.
- `interfaces/` own shared runtime contracts.
- `orchestration/` owns generic signing execution and activation/deployment orchestration.
- `signers/algorithms/` own algorithm-level signing behavior.
- `chainAdaptors/` own chain-specific intent shape and final serialization.
- `workers/` own runtime transport to WASM worker transports.

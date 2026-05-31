# Refactor 5x: Cross-Platform SDK Readiness

Date created: 2026-05-27
Status: in progress. Phases 0 and 1 are complete, the browser platform runtime
exists, and Phase 2 is partially wired. The next implementation slice is the
ECDSA client-bootstrap signer-crypto boundary.

## Scope

This refactor prepares the SDK for future iOS and embedded/Linux targets while
keeping the current browser SDK as the only active product target.

The main goal is to isolate browser-only dependencies behind explicit platform
ports and make the existing Rust/WASM cryptography boundary coarser, more
opaque, and easier to reuse from native SDKs. The current TypeScript SDK should
remain the public web surface. The current browser behavior should stay
unchanged during this refactor.

Future target examples:

- iOS SDK using Swift, Keychain, AuthenticationServices passkeys, and native
  Rust bindings.
- Embedded/Linux SDK for Raspberry Pi-class devices using SQLite or filesystem
  storage, optional TPM/FIDO2 hardware, and native Rust libraries or a local
  daemon.
- Browser SDK using IndexedDB, WebAuthn, iframe isolation, Web Workers, and
  WASM packages.

## Current Crypto Baseline

Most cryptographic implementation work is already in Rust/WASM. The existing
codebase has dedicated Rust/WASM packages for NEAR signing, EVM signing, Tempo
signing, Ed25519 HSS client work, threshold PRF work, email OTP runtime, and
Shamir 3-pass runtime. The existing `crates/signer-core`,
`crates/signer-platform-web`, and `crates/signer-platform-ios` structure is also
already pointed toward shared Rust core plus platform-specific bindings.

This refactor is therefore a boundary-tightening pass across the existing
Rust/WASM crypto surfaces:

- TypeScript should call coarse signer commands instead of composing crypto
  helper steps.
- Rust/WASM should own derivation labels, salts, participant validation,
  threshold parameters, share mapping, internal protocol serialization, and
  lifecycle-sensitive crypto state.
- TypeScript should hold public routing/display facts, opaque state blobs,
  typed handles, and high-level workflow decisions.
- Platform-specific SDKs should call the same Rust core through native bindings
  or a local service without reimplementing crypto internals.

## Problem

The SDK already has a solid browser architecture, but browser APIs still leak
into central runtime construction and signing flows:

- `createSigningEnginePorts(...)` injects `IndexedDBManager` directly from
  `client/src/core/signingEngine/assembly/createPorts.ts`.
- WebAuthn PRF-derived client secret material is modeled as a browser-specific
  path in modules such as
  `client/src/core/signingEngine/session/passkey/ecdsaClientRoot.ts`.
- Worker operation contracts mix portable signer commands with browser Worker
  transport details in
  `client/src/core/signingEngine/workerManager/workerTypes.ts`.
- Persistence modules mix durable domain records with IndexedDB-specific
  managers, key ranges, and browser storage availability checks.
- Some TypeScript modules still know more about crypto-internal parameters than
  a future platform SDK should know: derivation source shape, role-local state
  layout, worker command granularity, protocol state blobs, and relayer payload
  assembly.
- `crates/signer-platform-ios` exists, but its early C ABI helpers still expose
  a narrow vector-replay style surface.

These are manageable for the browser SDK. They will create unnecessary churn
when adding native iOS or Linux SDKs unless the seams are made explicit first.

## Verified Codebase Impact

Verified on 2026-05-27 against the current codebase.

The most important finding is that the ECDSA HSS role-local bootstrap already
runs in Rust/WASM through `wasm/hss_client_signer/src/threshold_hss.rs` and the
`hssClient` worker. The current TypeScript boundary still exposes helper-level
crypto details and persists raw role-local state fields. The MVP should reshape
that boundary rather than move a large amount of crypto implementation.

Concrete browser-platform extraction points:

- `client/src/core/signingEngine/assembly/createPorts.ts` imports
  `IndexedDBManager` and returns it directly from `createSigningEnginePorts`.
- `client/src/core/signingEngine/assembly/createManagers.ts`,
  `assembly/ports/shared.ts`, `assembly/ports/registration.ts`,
  `assembly/ports/recovery.ts`, `assembly/ports/evmFamily.ts`, and
  `assembly/ports/near.ts` still wire IndexedDB through signing-engine ports.
- `client/src/core/signingEngine/workerManager/SignerWorkerManager.ts`
  constructs `IndexedDBManager`, `TouchIdPrompt`, and Worker transport directly.
- `client/src/core/signingEngine/interfaces/runtime.ts` and
  `interfaces/operationDeps.ts` expose `UnifiedIndexedDBManager` as a core
  runtime dependency.

Concrete signer-crypto boundary points:

- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
  exposes `buildThresholdEcdsaHssRoleLocalClientBootstrapWasm` as a helper-level
  wrapper with `clientRootShare32B64u`, `clientShare32B64u`,
  `mappedPrivateShare32B64u`, and `verifyingShare33B64u`.
- `client/src/core/types/signer-worker.ts` mirrors those helper-level fields in
  the worker request/result contract.
- `client/src/core/signingEngine/interfaces/signing.ts` models
  `ThresholdEcdsaHssRoleLocalClientState` with raw share fields and
  `clientCaitSithInput`.
- `client/src/core/signingEngine/SigningEngine.ts` and
  `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts` construct
  persisted key refs from those raw fields.
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
  directly calls `threshold_ecdsa_hss_role_local_client_bootstrap` and rebuilds
  the same TypeScript role-local state shape.

Concrete client-secret source points:

- `client/src/core/signingEngine/session/passkey/ecdsaClientRoot.ts` owns the
  WebCrypto HKDF label for passkey PRF to ECDSA client root derivation.
- `client/src/core/signingEngine/threshold/ecdsa/clientSecretSource.ts` already
  acts as the natural boundary for converting credential results and provided
  root shares into a normalized secret source.
- Current provisioning and recovery paths pass `clientRootShare32B64u` through
  several layers, including `SigningEngine.ts`,
  `session/passkey/ecdsaProvisioner.ts`, `session/passkey/ecdsaWarmCapabilityBootstrap.ts`,
  `flows/signEvmFamily/provisionPlan.ts`, and `flows/recovery/ecdsaExportFlow.ts`.

Concrete persistence impact:

- `client/src/core/signingEngine/session/persistence/records.ts` normalizes and
  persists `ecdsaHssRoleLocalClientState` with raw role-local fields.
- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  rebuilds key refs from `clientAdditiveShare32B64u` and
  `ecdsaHssRoleLocalClientState`.
- Opaque state migration affects warm-session stores, key-ref builders, export
  flows, and tests that currently assert raw share availability.

MVP code changes from this verification:

1. Add a browser `PlatformRuntime` adapter and pass it into signing-engine
   assembly instead of importing `IndexedDBManager` inside core signing modules.
2. Add `SignerCryptoPort.prepareEcdsaClientBootstrap` and
   `SignerCryptoPort.finalizeEcdsaClientBootstrap` as the first coarse crypto
   commands, backed by the existing `hssClient` worker/WASM path.
3. Convert the ECDSA bootstrap output from raw share fields to a pending local
   state blob, relayer-facing client bootstrap facts, and a finalized ready
   opaque role-local state blob after relayer public identity is available.
4. Move passkey PRF to client-root derivation behind the secret-source boundary,
   preferably into Rust/WASM for the ECDSA HSS slice so TypeScript no longer
   owns the HKDF label.
5. Update persistence records and key-ref builders to store the opaque state
   blob plus public routing facts.
6. Update ECDSA export to consume the opaque role-local state blob rather than
   re-deriving from `clientRootShare32B64u` and public identity fields.
7. Replace tests that assert raw internal shares with tests that assert public
   facts, prepare client-bootstrap facts, ready opaque-state presence, and
   parity against current fixtures.

## Target Architecture

The long-term shape should be:

```mermaid
flowchart TD
  WEB["Browser SDK"] --> PORTS["Platform Ports"]
  IOS["iOS SDK"] --> PORTS
  LINUX["Linux / Embedded SDK"] --> PORTS

  PORTS --> CORE_TS["High-Level SDK Orchestration"]
  CORE_TS --> CRYPTO["SignerCryptoPort"]
  CRYPTO --> RUST["Rust Core + WASM / Native Bindings"]

  WEB --> WEB_IMPL["Browser Adapters: IndexedDB, WebAuthn, Workers, Fetch"]
  IOS --> IOS_IMPL["iOS Adapters: Keychain, AuthenticationServices, Native Rust"]
  LINUX --> LINUX_IMPL["Linux Adapters: SQLite, Filesystem, TPM/FIDO2, Native Rust"]

  RUST --> WASM["WASM Bindings"]
  RUST --> SWIFT["Swift / C ABI Bindings"]
  RUST --> NATIVE["Native Linux Library / Daemon"]
```

Ownership rules:

- Platform adapters own browser, iOS, and Linux API calls.
- Portable TypeScript owns SDK-facing orchestration, platform dispatch,
  persistence routing, and UI/session workflow decisions while it remains
  web-first.
- Rust core and WASM/native bindings own crypto internals, deterministic
  protocol logic, codecs, signer command execution, and formally checkable
  invariants.
- Persistence/request compatibility code stays at the boundary parser layer.
- Obsolete paths are deleted after replacement.

## Design Principles

1. Keep the browser SDK behavior stable while changing dependency shape.
2. Make platform APIs injectable through narrow required ports.
3. Normalize raw platform records once, then pass precise internal types.
4. Model device secret sources as discriminated unions.
5. Separate signer operations from worker/thread/native transport.
6. Prefer coarse Rust/WASM signer commands over exposing crypto helper
   pipelines to TypeScript.
7. Avoid permanent dual paths. Each migration phase should end with one active
   implementation path.

## Platform Port Targets

Add a platform layer under `client/src/core/platform/`.

Initial contracts:

```ts
export type PlatformKind = 'browser' | 'ios' | 'linux_embedded';

export type PlatformRuntime = {
  kind: PlatformKind;
  storage: DurableRecordStore;
  secrets: SecureSecretStore;
  authenticator: AuthenticatorPort;
  signerCrypto: SignerCryptoPort;
  http: HttpTransport;
  clock: ClockPort;
  random: RandomSource;
};
```

Port decisions for this refactor:

- `DurableRecordStore`: use typed repository batches for the specific
  signing-session records touched by this refactor. This port is a typed
  persistence boundary rather than a generic key/value database abstraction.
  The browser implementation may keep delegating to existing IndexedDB
  repositories, while core signing code receives normalized records through
  typed operations such as "load ECDSA role-local material", "persist ECDSA
  role-local material", and "cleanup malformed signing-session records".
  Generic `collection` / `key` get/put helpers are acceptable only as temporary
  scaffolding while the typed batch methods land.
- `SecureSecretStore`: seal, unseal, rotate, delete, and inspect secret handles.
- `AuthenticatorPort`: passkey/WebAuthn/native credential registration and
  assertion flows with branch-specific input and output records. It must return
  enough boundary-normalized material for registration authority verification,
  assertion verification, PRF/HMAC-secret derivation, credential identity, and
  user-cancel/error handling. See the contract below.
- `UserPresencePort`: local biometric/touch/PIN confirmation when separate from
  credential assertion.
- `SignerCryptoPort`: portable signer commands that hide browser Worker
  mechanics. The first active commands are
  `prepareEcdsaClientBootstrap` and `finalizeEcdsaClientBootstrap`. Additional
  hash, encode, presign, sign, and open/export operations should be added only
  when core call sites move onto the port, preferably as protocol-level commands
  when that reduces TypeScript knowledge of crypto internals.
- `HttpTransport`: relayer requests with explicit auth mode and timeout.
- `ClockPort`: `nowMs`, deadline helpers, and test overrides.
- `RandomSource`: cryptographic randomness.
- `BackgroundRuntime`: optional worker/thread/local-daemon execution.

The first implementation should be `createBrowserPlatformRuntime(...)`, which
wraps the existing IndexedDB, WebAuthn, Worker, Fetch, WebCrypto, and timer
paths.

### Platform Capability Matrix

This refactor ships only the browser runtime. Future platform branches remain
typed so the public contracts can settle early, but unsupported branches must
fail at adapter dispatch with typed errors.

| Capability | Browser MVP | iOS Future | Linux/Embedded Future |
| --- | --- | --- | --- |
| Durable storage | IndexedDB repositories behind typed batches | Keychain plus local database | SQLite or filesystem store with process-level locking |
| User credential | WebAuthn create/get through `AuthenticatorPort` | AuthenticationServices or Secure Enclave-backed app key | FIDO2/HMAC-secret, TPM, or local signer daemon |
| Client secret source | `webauthn_prf_first`, `email_otp_worker_session` | `secure_enclave_wrapped_secret` or passkey-backed branch | `fido2_hmac_secret`, TPM-backed, or daemon handle |
| Signer crypto | Browser Worker or direct WASM through `SignerCryptoPort` | Native binding wrapping `crates/signer-core` | Native crate, C ABI, or authenticated local service |
| Relayer transport | `fetch` through `HttpTransport` | native HTTPS client | native HTTPS client or daemon request |
| Public API in this refactor | yes | no | no |

Android, React Native, Node-only, Cloudflare Worker, and public native SDK APIs
are explicit non-goals for this refactor. If one becomes a target, add a new
capability column and acceptance criteria before implementing code.

### Contract Hardening Rules

- `docs/refactor-5x-cross-platform.md` is the canonical contract until the code
  is fully updated. `client/src/core/platform/types.ts` must be tightened to
  match the contract before new core call sites consume a port.
- Every port method used by core code must have exact input, success, command
  failure, invocation failure, and unsupported-branch shapes.
- Port contracts use required identity, auth, session, protocol, and lifecycle
  fields. Optional fields are limited to UI/display metadata and callbacks.
- Temporary generic scaffolding, such as generic durable-record get/put/delete,
  must be removed before the affected core path is migrated to the platform
  runtime.
- Unsupported future branches return typed dispatch failures from the active
  adapter. Core functions accept only the concrete branch they can handle.

### AuthenticatorPort Contract

The authenticator port should expose explicit operation branches instead of one
broad "run credential" bag:

```ts
type AuthenticatorOperation =
  | {
      kind: 'create_passkey';
      rpId: string;
      userHandleB64u: string;
      challengeB64u: string;
      requirePrfFirst: true;
      authenticatorOptions?: AuthenticatorOptions;
    }
  | {
      kind: 'create_passkey';
      rpId: string;
      userHandleB64u: string;
      challengeB64u: string;
      requirePrfFirst: false;
      authenticatorOptions?: AuthenticatorOptions;
    }
  | {
      kind: 'get_passkey';
      rpId: string;
      credentialIdB64u: string;
      challengeB64u: string;
      requirePrfFirst: true;
    }
  | {
      kind: 'get_passkey';
      rpId: string;
      credentialIdB64u: string;
      challengeB64u: string;
      requirePrfFirst: false;
    };

type AuthenticatorResult =
  | {
      ok: true;
      operation: 'create_passkey';
      requirePrfFirst: true;
      credential: WebAuthnRegistrationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prf: {
        kind: 'required';
        prfFirstB64u: string;
      };
    }
  | {
      ok: true;
      operation: 'create_passkey';
      requirePrfFirst: false;
      credential: WebAuthnRegistrationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prf:
        | {
            kind: 'available_without_requirement';
            prfFirstB64u: string;
          }
        | {
            kind: 'not_requested_or_unavailable';
            prfFirstB64u?: never;
          };
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: true;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prf: {
        kind: 'required';
        prfFirstB64u: string;
      };
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: false;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prf:
        | {
            kind: 'available_without_requirement';
            prfFirstB64u: string;
          }
        | {
            kind: 'not_requested_or_unavailable';
            prfFirstB64u?: never;
          };
    }
  | {
      ok: false;
      code:
        | 'unavailable'
        | 'cancelled'
        | 'not_allowed'
        | 'prf_unavailable'
        | 'invalid_credential'
        | 'platform_error';
      message: string;
    };
```

Browser WebAuthn raw results normalize at this port boundary. Core registration
and signing code should receive the precise success branch it asked for; raw
browser credential objects and broad optional auth bags stay at the boundary.
If an operation sets `requirePrfFirst: true`, success must include
`prf.kind: 'required'` and `prfFirstB64u`; missing PRF output is a
`prf_unavailable` failure. If PRF is not required, the success branch still
states whether PRF was returned. Core ECDSA provisioning accepts only the
`required` PRF branch.

## Client Secret Source Model

Browser passkey PRF should become one branch of a platform-neutral secret-source
union.

Target internal shape:

```ts
type ClientSecretSource =
  | {
      kind: 'webauthn_prf_first';
      prfFirstB64u: string;
      rpId: string;
      credentialIdB64u: string;
    }
  | {
      kind: 'secure_enclave_wrapped_secret';
      keyId: string;
      accessGroup: string;
    }
  | {
      kind: 'fido2_hmac_secret';
      credentialIdB64u: string;
      rpId: string;
    }
  | {
      kind: 'email_otp_worker_session';
      sessionId: string;
    };
```

Rules:

- Browser WebAuthn code builds `webauthn_prf_first` only after the
  `AuthenticatorPort` has returned a concrete PRF result for a specific
  credential, RP ID, and challenge.
- `email_otp_worker_session` means a worker-owned session handle for a
  previously normalized Email OTP registration or signing session. The handle is
  opaque to core TypeScript. Core code must not receive Email OTP root-share
  bytes through this branch.
- iOS can later build `secure_enclave_wrapped_secret` or a passkey-backed
  branch. Browser dispatch returns `unsupported_secret_source` for this branch
  until a real adapter exists.
- Linux/embedded can later build `fido2_hmac_secret`, TPM-backed, or
  local-daemon-backed branches. Browser dispatch returns
  `unsupported_secret_source` for this branch until a real adapter exists.
- Core provisioning functions accept the narrow branch they support.
- Unsupported branches fail at boundary dispatch with typed errors.

Required branch fields are identity, not display metadata. Builders must reject
empty `rpId`, `credentialIdB64u`, `sessionId`, `keyId`, or `accessGroup` values
at the boundary.

Boundary builder requirements:

- `buildWebAuthnPrfFirstSecretSource(...)` accepts only the authenticator success
  branch with `prf.kind: 'required'`.
- `buildEmailOtpWorkerSessionSecretSource(...)` accepts only a worker-issued
  session handle that has already been bound to wallet id, user id, action, and
  operation at the Email OTP boundary.
- `buildSecureEnclaveWrappedSecretSource(...)` and
  `buildFido2HmacSecretSource(...)` are allowed as typed future builders, and
  the browser adapter returns `unsupported_secret_source` for those branches.
- Type fixtures must reject direct object-literal construction with missing
  identity fields, branch spreads that mix `sessionId` with passkey fields, and
  casts from raw records into `ClientSecretSource`.

## MVP Boundary Target

The minimum useful version of this refactor should keep iOS and embedded SDKs
out of scope. It should make the current browser SDK consume a platform runtime
and a coarse signer-crypto boundary that a future native SDK can implement.

MVP target commands:

```ts
type SignerCryptoPort = {
  prepareEcdsaClientBootstrap(
    input: PrepareEcdsaClientBootstrapInput,
  ): Promise<PrepareEcdsaClientBootstrapResult>;
  finalizeEcdsaClientBootstrap(
    input: FinalizeEcdsaClientBootstrapInput,
  ): Promise<FinalizeEcdsaClientBootstrapResult>;
};
```

MVP Rust/WASM ownership:

- validate `ClientSecretSource` branch inputs after TypeScript boundary parsing
- own HKDF labels and derivation constants
- derive client root share material
- map additive shares to threshold-signatures shares
- validate secp256k1 public material
- construct pending and ready role-local client state as opaque state blobs
- return public facts needed by TypeScript routing and persistence
- return typed crypto/protocol error codes

MVP TypeScript ownership:

- collect WebAuthn or platform credential results
- build the `ClientSecretSource`
- call the signer crypto prepare command
- send the returned client bootstrap facts to the relayer with route auth,
  request id, TTL, session policy, and wallet-signing-session context
- call the signer crypto finalize command after the relayer returns public
  identity
- store ready opaque state blobs
- route public facts
- run user-visible workflow, retries, UI, and persistence policy

Excluded signer-crypto fields: relayer URL, route auth, JWT/cookie routing,
request id, keygen session id, wallet signing session id, threshold session id,
TTL, remaining uses, UI prompt state, and diagnostics. Those values stay in
TypeScript orchestration and relayer request builders.

MVP input and output shape:

```ts
type PrepareEcdsaClientBootstrapInput = {
  kind: 'prepare_ecdsa_client_bootstrap_v1';
  algorithm: 'ecdsa_hss_secp256k1_role_local_v1';
  context: {
    walletId: WalletId;
    rpId: RpId;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: EcdsaThresholdKeyId;
    signingRootId: EcdsaHssSigningRootId;
    signingRootVersion: EcdsaHssSigningRootVersion;
    keyPurpose: 'evm-signing';
    keyVersion: 'v1';
  };
  participants: {
    clientParticipantId: 1;
    relayerParticipantId: 2;
    participantIds: readonly [1, 2];
  };
  secretSource: WebAuthnPrfFirstSecretSource | EmailOtpWorkerSessionSecretSource;
};

type PrepareEcdsaClientBootstrapOutput = {
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  clientBootstrap: {
    contextBinding32B64u: string;
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientShareRetryCounter: number;
    participantId: 1;
  };
  publicFacts: {
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientVerifyingShareB64u: string;
  };
};

type FinalizeEcdsaClientBootstrapInput = {
  kind: 'finalize_ecdsa_client_bootstrap_v1';
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  relayerPublicIdentity: {
    relayerKeyId: string;
    relayerPublicKey33B64u: string;
    groupPublicKey33B64u: string;
    ethereumAddress: `0x${string}`;
  };
};

type FinalizeEcdsaClientBootstrapOutput = {
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: {
    hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
    clientVerifyingShareB64u: string;
    relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
    groupPublicKey33B64u: string;
    ethereumAddress: `0x${string}`;
  };
};

type EcdsaRoleLocalPendingStateBlob = {
  kind: 'ecdsa_role_local_pending_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

type EcdsaRoleLocalReadyStateBlob = {
  kind: 'ecdsa_role_local_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

type EcdsaClientRootPublicKey33B64u = string & {
  readonly __brand: 'EcdsaClientRootPublicKey33B64u';
};

type EcdsaHssClientSharePublicKey33B64u = string & {
  readonly __brand: 'EcdsaHssClientSharePublicKey33B64u';
};

type EcdsaRelayerHssPublicKey33B64u = string & {
  readonly __brand: 'EcdsaRelayerHssPublicKey33B64u';
};

type EcdsaClientRootProof = {
  kind: 'ecdsa_client_root_proof_v1';
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  signatureB64u: string;
  messageB64u: string;
};

type SignerCryptoInvocationErrorCode =
  | 'unavailable'
  | 'worker_transport_failure'
  | 'native_binding_failure'
  | 'timeout';

type SignerCryptoResult<Ok, CommandCode extends string> =
  | {
      ok: true;
      value: Ok;
      failure?: never;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      failure: 'command';
      code: CommandCode;
      message: string;
      value?: never;
    }
  | {
      ok: false;
      failure: 'invocation';
      code: SignerCryptoInvocationErrorCode;
      message: string;
      value?: never;
    };

type PrepareEcdsaClientBootstrapErrorCode =
  | 'unsupported_secret_source'
  | 'invalid_secret_source'
  | 'invalid_context'
  | 'invalid_threshold_parameters'
  | 'invalid_public_material'
  | 'crypto_failure';

type FinalizeEcdsaClientBootstrapErrorCode =
  | 'invalid_pending_state'
  | 'invalid_relayer_public_identity'
  | 'public_identity_mismatch'
  | 'crypto_failure';
```

The current parity target preserves the existing ECDSA HSS derivation context.
`chainTarget` is a public routing and persistence field unless signer-core
fixtures intentionally revise the context binding.

This MVP proves the future iOS/Linux seam because native adapters only need to
provide a secret source, storage, signer crypto, and relayer transport.

Opaque-state ownership:

- `crates/signer-core` owns the internal serialized role-local state format,
  version, derivation labels, share mapping, and validation.
- `wasm/hss_client_signer` exposes the browser binding for the signer-core
  command and does not define a second state format.
- TypeScript treats `pendingStateBlob.stateBlobB64u` and
  `stateBlob.stateBlobB64u` as opaque. It may persist ready blobs, compare
  presence, and pass blobs back into signer-crypto commands. Parsing share
  fields out of the blob belongs in signer-core.
- Public routing/index fields stay outside the blob: `walletId`, `rpId`,
  `chainTarget`, `keyHandle`, `ecdsaThresholdKeyId`, owner address, participant
  ids, signing-root identity, and the public facts returned by the command.
- Persistence normalizers validate that public scalar mirrors match the record's
  public facts. They cannot validate blob internals.

ECDSA bootstrap state machine:

1. `collect_secret_source`: platform adapter returns a concrete
   `WebAuthnPrfFirstSecretSource` or `EmailOtpWorkerSessionSecretSource`.
2. `prepare`: core passes full context, participant ids, and the secret source to
   `SignerCryptoPort.prepareEcdsaClientBootstrap(...)`.
3. `relayer_bootstrap`: TypeScript sends `clientBootstrap` plus route auth,
   request id, session policy, TTL, and wallet-signing-session context to the
   relayer. Those transport fields never enter signer-core.
4. `finalize`: TypeScript passes the `pendingStateBlob` and normalized relayer
   public identity to `SignerCryptoPort.finalizeEcdsaClientBootstrap(...)`.
5. `persist_ready`: the durable store writes the ready state blob and required
   public facts in a single typed repository batch.
6. `cleanup_failed`: pending blobs are process-local unless a future phase adds
   durable pending recovery. Failed prepare or finalize attempts do not write a
   ready role-local record.

Invalid transitions:

- `finalize` without a pending blob returns `invalid_pending_state`.
- `persist_ready` without finalized relayer public identity is rejected by the
  repository input type.
- A ready state blob cannot be passed to `finalize`.
- A pending state blob cannot be used by signing, export, or key-ref builders.
- A relayer public identity whose HSS key or group public key disagrees with the
  pending state returns `public_identity_mismatch`.

Persistence migration contract:

```ts
type EcdsaRoleLocalPublicFacts = {
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: EcdsaHssSigningRootId;
  signingRootVersion: EcdsaHssSigningRootVersion;
  clientParticipantId: 1;
  relayerParticipantId: 2;
  participantIds: readonly [1, 2];
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: `0x${string}`;
};

type EcdsaRoleLocalReadyRecord = {
  kind: 'ecdsa_role_local_ready_record_v1';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
};

type EcdsaRoleLocalRawRecord =
  | {
      kind: 'legacy_raw_role_local_v1';
      clientShare32B64u: string;
      clientPublicKey33B64u: string;
      clientCaitSithInput: {
        mappedPrivateShare32B64u: string;
        verifyingShare33B64u: string;
      };
      publicFacts: EcdsaRoleLocalPublicFacts;
    }
  | {
      kind: 'ready_blob_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
    };

type EcdsaRoleLocalRecordParseResult =
  | {
      ok: true;
      record: EcdsaRoleLocalReadyRecord;
      cleanup?: never;
    }
  | {
      ok: false;
      cleanup: 'delete_malformed_record' | 'reauth_required';
      reason: string;
      record?: never;
    };
```

Migration rules:

- The persistence boundary parser is the only code that reads
  `legacy_raw_role_local_v1`.
- New writes always use `ready_blob_v1`.
- Core ECDSA signing, export, recovery, warm-session, and key-ref code accepts
  `EcdsaRoleLocalReadyRecord` only.
- The parser validates required public scalar mirrors: wallet id, RP id,
  `chainTarget`, key handle, threshold key id, signing-root identity, participant
  ids, HSS client-share public key, relayer HSS public key, group public key, and
  owner address.
- Legacy parser code is deleted when the in-development data reset removes old
  role-local rows.
- Tests cover valid legacy read normalization, malformed legacy cleanup, new
  write shape, and rejection of raw-share fields outside the parser module.

## Phase 0: Boundary Inventory

Create an inventory document or checked script that lists platform-boundary
usage.

Tasks:

- [x] Inventory direct `IndexedDBManager`, `IDB*`, and `idb` imports outside
      storage adapters.
- [x] Inventory direct `navigator.credentials`, `window`, `document`,
      `MessageChannel`, `Worker`, `localStorage`, and `crypto.subtle` use in
      signing paths.
- [x] Inventory signer operation calls that are conceptually portable:
      hashing, tx encoding, key derivation, signature verification, HSS
      ceremony commands, and presignature commands.
- [x] Inventory TypeScript modules that still assemble crypto-internal
      parameter sets or relayer client-bootstrap payloads from helper-level
      crypto outputs.
- [x] Inventory persistence record types that combine raw storage records,
      normalized domain records, public identity, and hot signer material.
- [x] Inventory current Rust core coverage in `crates/signer-core`,
      `crates/signer-platform-web`, `crates/signer-platform-ios`, and
      `wasm/*`, with emphasis on which high-level workflows already have Rust
      coverage.

Deliverable:

- `docs/refactor-5x-cross-platform-inventory.md`, or a section appended to this
  document, containing the boundary map and recommended first extraction
  targets.

Validation:

- Type-check only if inventory work adds exported types or scripts.

## Phase 1: Add Neutral Platform Contracts

Add platform contracts without changing runtime behavior.

Tasks:

- [x] Add `client/src/core/platform/types.ts`.
- [x] Define `PlatformRuntime` and the first port interfaces.
- [x] Use discriminated unions for platform kind, secret source kind, auth
      operation kind, storage result, and signer crypto result.
- [x] Add `assertNever` exhaustiveness checks for platform-kind dispatch.
- [x] Add type fixtures for invalid port and secret-source combinations.
- [x] Keep all existing browser managers as implementation details.

Acceptance criteria:

- No current signing, registration, recovery, or export flow changes behavior.
- New contracts compile under `sdk/tsconfig.build.json`.
- No direct platform runtime dependency is introduced into Rust or server code.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`

## Phase 1.5: Harden Contracts Before More Call-Site Migration

Tighten the scaffold contracts so later phases implement the same shapes the
spec describes. This phase is documentation-driven and type-driven; it should
land before migrating more core ECDSA bootstrap code onto `PlatformRuntime`.

Tasks:

- [ ] Update `client/src/core/platform/types.ts` so `PlatformRuntime`,
      `AuthenticatorPort`, `ClientSecretSource`, `SignerCryptoPort`, and
      `DurableRecordStore` match this document's canonical contracts.
- [ ] Add `finalizeEcdsaClientBootstrap` to `SignerCryptoPort` with the
      `SignerCryptoResult` envelope.
- [ ] Split signer-crypto command errors from invocation errors.
- [ ] Replace optional PRF success output with explicit `prf.kind` branches.
- [ ] Replace generic durable-record get/put/delete scaffolding with the typed
      ECDSA repository batch signatures used by Phase 3.
- [ ] Add type fixtures for invalid authenticator PRF branches, unsupported
      future secret sources in MVP ECDSA bootstrap, ready/pending blob mixups,
      and broad object spreads into `ClientSecretSource`.
- [ ] Add an import guard that fails when core signing/session modules import
      `IndexedDBManager`, `Worker`, `MessageChannel`, `navigator.credentials`,
      `window`, `document`, or raw HSS share field names.

Acceptance criteria:

- `client/src/core/platform/types.ts` no longer exposes loose bootstrap input
  shapes such as raw `walletId`, raw `participantIds: readonly number[]`, or
  optional PRF success fields for core-facing methods.
- Future iOS/Linux branches are represented only as typed unsupported dispatch
  failures in the browser adapter.
- Core-facing port tests prove pending blobs cannot be used as ready blobs and
  HSS client-share public keys cannot verify client-root proofs.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- `pnpm -C tests exec playwright test ./unit/signerDomain.guard.unit.test.ts ./unit/signer-worker.guards.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts ./unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts --reporter=line`

## Phase 2: Wrap Current Browser Implementations

Build the browser platform runtime as a pass-through adapter over existing code.
Keep this phase focused on the ports needed by the ECDSA bootstrap slice; broad
runtime coverage can follow actual call-site migration.

Tasks:

- [x] Add `client/src/core/platform/browser/createBrowserPlatformRuntime.ts`.
- [x] Add the initial browser `DurableRecordStore` scaffold over existing
      IndexedDB infrastructure.
- [ ] Wire `DurableRecordStore` to typed ECDSA signing-session repository
      batches.
- [ ] Wrap WebAuthn credential collection behind `AuthenticatorPort`.
- [ ] Wrap the ECDSA client-bootstrap hss-client worker dispatch behind
      `SignerCryptoPort` as a prepare/finalize operation pair.
- [x] Wrap `fetch`, timers, and WebCrypto randomness behind `HttpTransport`,
      `ClockPort`, and `RandomSource`.
- [x] Update `createSigningEnginePorts(...)` to receive a platform runtime
      instead of importing `IndexedDBManager` directly.
- [x] Keep browser adapter construction in the existing assembly layer.

Acceptance criteria:

- `client/src/core/signingEngine/assembly/createPorts.ts` no longer imports
  `IndexedDBManager` directly.
- Current SDK browser flows still use the same underlying IndexedDB and
  Rust/WASM Worker code through the adapter.
- ECDSA bootstrap core code receives typed repository records and signer crypto
  results through the platform runtime.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- `pnpm -C tests exec playwright test ./unit/signer-worker.guards.test.ts ./unit/workerTransport.multichainTimeout.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts --reporter=line` when the hss-client worker adapter is touched.

## Phase 3: Split Persistence Records From IndexedDB Drivers

Move only the persistence records affected by the ECDSA role-local state change
into browser-neutral modules. Refactor 45 already consolidated the wider
IndexedDB schema and repository surface; this phase should stay limited to
ECDSA role-local material rather than unrelated wallet/auth-method/signer
tables.

Tasks:

- [ ] Split ECDSA HSS role-local raw storage shapes from normalized internal
      records.
- [ ] Move ECDSA role-local record parsing, version normalization, and cleanup
      decisions into `client/src/core/signingEngine/session/persistence/records.ts`
      or a new neutral persistence module.
- [ ] Keep IndexedDB schema, indexes, key ranges, and transactions inside
      `client/src/core/indexedDB/*`.
- [ ] Add strict internal unions for ECDSA role-local session records:
      ready passkey material, ready Email OTP material, reauth-required
      material, and invalid or cleanup-only raw records.
- [ ] Keep Ed25519 record changes out of this phase unless a touched ECDSA
      parser requires a shared helper.
- [ ] Remove repeated ECDSA role-local compatibility parsing from core signing
      modules after the neutral parser exists.

Acceptance criteria:

- Core ECDSA signing/session logic accepts normalized records only.
- IndexedDB raw ECDSA role-local shapes do not leak beyond the storage adapter
  and parser.
- ECDSA role-local compatibility branches are concentrated in boundary parser
  modules and scheduled for deletion with the in-development data reset.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- Targeted persistence record tests and existing malformed-record cleanup tests.

## Phase 4: Split Signer Operations From Transport

Separate portable signer commands from browser Worker mechanics while preserving
the current Rust/WASM implementations.

Ordering decision: start with one coarse bootstrap pair before expanding the
worker surface. A one-for-one wrapper around every current worker message would
create a large transitional API that still mirrors browser Worker mechanics.
The next slice should define and wire only
`SignerCryptoPort.prepareEcdsaClientBootstrap` and
`SignerCryptoPort.finalizeEcdsaClientBootstrap`, then use that slice to shape
the general crypto-port conventions. Broader worker wrapping can happen later
only for operations that core call sites actively move onto `SignerCryptoPort`.

Phase 4 defines the TypeScript port contract and browser transport adapter for
those operations. Phase 6 implements the cryptographic internals behind the same
operations in `crates/signer-core` and exposes them through
`wasm/hss_client_signer`. Keeping those steps separate lets the SDK call sites
move to a stable transport-free contract before the Rust/WASM implementation
absorbs HKDF, share mapping, pending state serialization, and ready state
finalization.

Key-domain safety requirement:

The ECDSA bootstrap path must make client-root keys, HSS client-share keys, and
relayer HSS keys structurally distinct. The previous string-shaped boundary made
it possible to verify a client-root proof against the HSS client-share public
key because both were represented as generic compressed secp256k1 public keys.

Required naming and type changes:

- Rename `clientPublicKey33B64u` to `hssClientSharePublicKey33B64u` anywhere it
  identifies the HSS ceremony/client-share public key.
- Rename `clientRootProof.publicKey33B64u` to
  `clientRootProof.clientRootPublicKey33B64u`.
- Add branded/opaque TypeScript types:
  `EcdsaClientRootPublicKey33B64u`,
  `EcdsaHssClientSharePublicKey33B64u`, and
  `EcdsaRelayerHssPublicKey33B64u`.
- Make root-proof verification accept a narrow proof object:
  `verifyClientRootProof(proof: EcdsaClientRootProof): Result<...>`. The proof
  object carries `clientRootPublicKey33B64u`, so callers cannot supply an HSS
  client-share public key as the verifier.
- Parse HSS bootstrap identity and client-root proof identity through separate
  boundary parsers. Combine the normalized results only after both branches are
  independently validated.

Tasks:

- [ ] Define the `prepareEcdsaClientBootstrap` and
      `finalizeEcdsaClientBootstrap` signer-crypto operations
      independent of Web Worker transport.
- [ ] Split key-domain types for ECDSA client-root, HSS client-share, and
      relayer HSS public keys before wiring the bootstrap port.
- [ ] Map the browser hss-client worker request/response for these operations in
      one browser crypto adapter.
- [ ] Use the ECDSA bootstrap slice to establish the result-envelope and error
      conventions for future crypto operations.
- [ ] Keep command payloads narrow, structured, and operation-specific.
- [ ] Defer broad one-for-one worker wrapping until a core call site is ready to
      consume that operation through `SignerCryptoPort`.
- [ ] Keep direct-call and native-call adapters possible for future iOS/Linux.
- [ ] Convert boolean-success worker results to `Result`-style unions where the
      operation carries cryptographic material or lifecycle state.
- [ ] Add a runtime regression test proving a proof signed by the client root
      share rejects when verified against an HSS client-share public key.
- [ ] Add a type fixture proving `EcdsaHssClientSharePublicKey33B64u` cannot be
      passed where `EcdsaClientRootPublicKey33B64u` is required.

Acceptance criteria:

- ECDSA client-bootstrap core code calls `SignerCryptoPort` for prepare and
  finalize.
- The ECDSA bootstrap browser Worker request/response envelopes live in the
  browser crypto adapter.
- Existing Rust/WASM crypto remains the implementation behind the browser
  crypto adapter.
- Future native bindings can implement the same crypto port without importing
  browser Worker types.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- Existing worker operation unit tests and HSS active-path smoke tests when HSS
  wrappers are touched.

## Phase 5: Make Authenticator And Secret Sources Platform-Neutral

Replace passkey-specific secret derivation entrypoints in core provisioning with
strict secret-source branches.

Tasks:

- [ ] Add `ClientSecretSource` and branch-specific builders.
- [ ] Convert browser WebAuthn credential parsing into a boundary builder that
      returns `webauthn_prf_first`.
- [ ] Define `email_otp_worker_session` as a worker-owned opaque handle and
      reject attempts to pass Email OTP root-share bytes through core TypeScript.
- [ ] Make ECDSA and Ed25519 provisioning functions accept exact supported
      secret-source branches.
- [ ] Keep unsupported future branches as explicit dispatch failures, not broad
      optional bags.
- [ ] Add type fixtures rejecting missing identity fields for every concrete
      branch.

Acceptance criteria:

- WebAuthn PRF is no longer assumed by core provisioning signatures.
- Browser behavior remains unchanged because the browser adapter builds the same
  PRF-derived material.
- Future iOS/Linux branches can be added without changing current browser
  provisioning call sites.

Validation:

- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- Targeted tests around
  `derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst` and current
  registration/login bootstrap flows.

## Phase 6: Internalize One Crypto Boundary Slice

Use the existing Rust/WASM crypto baseline to move one helper-shaped TypeScript
workflow behind a coarse signer command. This is the MVP of the cryptographic
abstraction work.

Recommended pilot:

- ECDSA client bootstrap and role-local client state construction.

Why this slice:

- It is security-sensitive and already depends on Rust/WASM crypto helpers.
- It has a concrete future-platform seam: browser WebAuthn PRF today, iOS or
  embedded secret source later.
- It can return a small set of public facts plus an opaque state blob.
- It reduces TypeScript knowledge of derivation labels, share mapping,
  secp256k1 validation, and role-local state layout.

Rust/WASM should own:

- HKDF labels and derivation constants.
- Client-root derivation from the accepted secret-source branch.
- Additive share mapping.
- secp256k1 public key validation and address derivation.
- Pending role-local state construction, ready role-local state finalization,
  and internal serialization.
- Crypto/protocol error codes.

Implementation home:

- Reusable HKDF, client-root derivation, additive-share mapping, secp256k1
  validation, pending state serialization, and ready state finalization land in
  `crates/signer-core`.
- `wasm/hss_client_signer` exposes the browser WASM binding for the signer-core
  command.
- Native bindings later wrap the same signer-core command. Shared protocol
  logic stays in signer-core instead of Swift, C, or platform-specific Rust
  crates.

TypeScript should own:

- Building a normalized `ClientSecretSource` from platform credential results.
- Passing account, chain, signing-root, and policy identities.
- Sending prepare output to the relayer with auth/session routing fields.
- Passing relayer public identity into finalize.
- Storing the opaque `EcdsaRoleLocalReadyStateBlob` envelope.
- Routing public facts.
- User workflow, retries, and UI.

Tasks:

- [ ] Define `prepareEcdsaClientBootstrap` and
      `finalizeEcdsaClientBootstrap` on `SignerCryptoPort`.
- [ ] Add the reusable signer-core command that implements HKDF/client-root
      derivation, share mapping, public fact validation, pending state
      serialization, and ready state finalization.
- [ ] Expose the signer-core command through `wasm/hss_client_signer`.
- [ ] Return `{ pendingStateBlob, clientBootstrap, publicFacts }` from prepare
      and `{ stateBlob, publicFacts }` from finalize.
- [ ] Replace the TypeScript helper pipeline with the coarse command.
- [ ] Delete the replaced TypeScript crypto-internal assembly path.
- [ ] Add parity fixtures for current browser PRF inputs, prepare output,
      relayer public identity input, and finalized public facts.
- [ ] Add native-binding vector replay coverage if the command lands in
      `crates/signer-platform-ios`.
- [ ] Record before/after browser JS, WASM, and lazy-flow asset sizes.

Acceptance criteria:

- ECDSA client bootstrap no longer exposes derivation internals or role-local
  state layout to TypeScript.
- The active browser path gets HKDF and role-local state construction from
  `crates/signer-core` through `wasm/hss_client_signer`.
- The ready role-local state blob is produced only after relayer public identity
  is supplied to finalize.
- Browser behavior remains equivalent under parity fixtures and current flow
  tests.
- Future native SDKs can call the same Rust core command with a platform-built
  secret source.
- The old TypeScript assembly path is removed.

Validation:

- `cargo test --manifest-path crates/signer-core/Cargo.toml`
- Relevant `cargo test` for the WASM package that exposes the command.
- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- Targeted ECDSA bootstrap/provisioning tests.
- Bundle-size check for affected SDK assets.

## Phase 7: Optional Portable State-Machine Pilot

After Phase 6 proves the coarse signer-command boundary, consider moving one
pure state machine into `crates/signer-core` if it clearly improves
cross-platform reuse or formal-verification coverage.

Good candidates:

- Signing operation planning and operation-id binding.
- ECDSA lane material readiness transitions.
- Budget admission and spend finalization projection.
- Threshold session lifecycle transitions.

Selection criteria:

- No browser API dependency.
- Small input and output surface.
- Clear invariants suitable for parity fixtures or Verus.
- Enough shared-platform value to justify Rust/WASM or native binding exposure.

Acceptance criteria:

- One portable core state machine exists in Rust with parity coverage.
- The browser uses the Rust path only when size and complexity remain acceptable.
- The old TypeScript implementation is removed after replacement.

Validation:

- `cargo test --manifest-path crates/signer-core/Cargo.toml`
- Relevant `cargo test` for a WASM package only if browser code calls it.
- `npx tsc --noEmit -p sdk/tsconfig.build.json`
- Relevant formal-verification or anti-drift target if added.

## Phase 8: Harden Native Binding Strategy

Prepare `crates/signer-platform-ios` and future Linux bindings for real SDK
surfaces.

Tasks:

- [ ] Replace null-pointer-only failure surfaces with a stable result envelope
      for C ABI functions that remain.
- [ ] Evaluate UniFFI for Swift bindings once the first real iOS API surface is
      known.
- [ ] Keep native bindings generated from or wrapping `signer-core`; shared
      protocol logic stays out of Swift or C.
- [ ] Add vector replay scripts for any newly exposed binding operation.
- [ ] Define a future Linux native binding shape: Rust crate, C ABI, or local
      signer daemon.

Acceptance criteria:

- Native binding surfaces return typed status and error information.
- iOS vector replay can compare native output with committed signer-core
  fixtures.
- The Rust core remains the single implementation of shared protocol logic.

Validation:

- `cargo test --manifest-path crates/signer-platform-ios/Cargo.toml`
- `crates/signer-platform-ios/scripts/run-swift-vector-replay.sh` when Swift
  coverage is touched.

## Suggested Implementation Order

1. Phase 0: boundary inventory. Complete; keep the inventory current when a
   touched file exposes a new browser dependency.
2. Phase 1: neutral platform contracts. Complete as a scaffold; tighten
   `DurableRecordStore`, `AuthenticatorPort`, `ClientSecretSource`, and
   `SignerCryptoPort` before using them in new core call sites.
3. Phase 1.5: contract hardening. Align `client/src/core/platform/types.ts`
   with this document, add finalize, split command/invocation errors, remove
   optional PRF success fields, and add guard/type fixtures.
4. Phase 2: browser runtime adapter for the ECDSA bootstrap slice. Finish typed
   ECDSA repository batches, browser WebAuthn collection, and the browser
   bootstrap prepare/finalize worker adapter.
5. Phase 3: narrow ECDSA persistence record split. Move only ECDSA HSS
   role-local records and key-ref builders onto normalized boundary parsers.
6. Phase 4: signer operation versus transport split for
   `prepareEcdsaClientBootstrap` and `finalizeEcdsaClientBootstrap`. This phase
   defines the operation shapes and maps the current hss-client Worker
   request/response into a transport-free crypto port.
7. Phase 5: platform-neutral ECDSA secret sources. Tighten
   `webauthn_prf_first` and `email_otp_worker_session` branches before moving
   active bootstrap call sites.
8. Phase 6: signer-core/WASM coarse ECDSA bootstrap command. Implement HKDF,
   share mapping, validation, pending state serialization, and ready state
   finalization in
   `crates/signer-core`, then expose the command through
   `wasm/hss_client_signer`.
9. Phase 7: optional portable state-machine pilot after the coarse command is
   active and stable.
10. Phase 8: native binding hardening after signer-core vectors exist.

## Implementation Spec Appendix

This appendix turns the phase narrative into an execution contract. Keep it in
sync with code while implementing the refactor. If a phase discovers a different
live path, update this section before changing the code so review can check the
intended boundary against the actual diff.

### Current Implementation Delta To Close

The current `client/src/core/platform/types.ts` scaffold is intentionally looser
than the target contract. Phase 1.5 must close these exact gaps before new core
call sites consume the platform runtime:

| Current symbol | Current gap | Target replacement |
| --- | --- | --- |
| `PlatformResult<Ok, Code>` | Conflates command failures and invocation failures. | `SignerCryptoResult<Ok, CommandCode>` with `failure: 'command' | 'invocation'`. |
| `DurableRecordStore.get/put/delete` | Generic collection/key/value storage leaks raw records into core. | Typed ECDSA role-local repository batches listed below. |
| `AuthenticatorPort.run(...)` | One broad operation with optional `prfFirstB64u`. | Branch-specific create/get passkey operations with `requirePrfFirst` and `prf.kind` success branches. |
| `ClientSecretSource` | Raw strings and direct object construction are still easy. | Branch-specific builders that return branded, normalized secret-source branches. |
| `PrepareEcdsaClientBootstrapInput` | Raw `walletId`, raw `rpId`, raw `participantIds: readonly number[]`, missing chain/signing-root context. | Full `PrepareEcdsaClientBootstrapInput` from this document, using branded identity types and `readonly [1, 2]`. |
| `PrepareEcdsaClientBootstrapOutput` | Returns a generic `stateBlobB64u`, `clientPublicKey33B64u`, and relayer payload blob. | `{ pendingStateBlob, clientBootstrap, publicFacts }` with HSS-specific key names. |
| `SignerCryptoPort` | Has prepare only. | Prepare and finalize pair with typed result envelopes. |

The active raw-share path to replace is:

- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
  `buildThresholdEcdsaHssRoleLocalClientBootstrapWasm(...)`.
- `client/src/core/types/signer-worker.ts`
  `WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapRequest` and
  `WasmBuildThresholdEcdsaHssRoleLocalClientBootstrapResult`.
- `client/src/core/signingEngine/interfaces/signing.ts`
  `ThresholdEcdsaHssRoleLocalClientState` and
  `ThresholdEcdsaBackendBinding.clientAdditiveShare32B64u`.
- `client/src/core/signingEngine/session/persistence/records.ts`
  `normalizeThresholdEcdsaHssRoleLocalClientState(...)`.
- `client/src/core/rpcClients/relayer/walletRegistration.ts`
  `buildWalletRegistrationEcdsaSessionBootstrap(...)` raw state assembly.
- `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
  direct construction of `ThresholdEcdsaHssRoleLocalClientState`.
- `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
  direct parsing/construction of `ThresholdEcdsaHssRoleLocalClientState`.
- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  key-ref construction that consumes raw role-local fields.
- `client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
  export paths that still depend on raw public/share fields.

Raw-field names that must disappear from active core signing/session/export
paths after Phase 6:

- `clientShare32B64u`
- `clientAdditiveShare32B64u`
- `mappedPrivateShare32B64u`
- `verifyingShare33B64u`
- `clientCaitSithInput`
- `clientPublicKey33B64u` when the value is the HSS client-share public key

The persistence boundary parser may mention legacy raw fields while the
in-development data reset still needs cleanup. New writes must never create
those fields.

### Phase 1.5 Exact Type Targets

Land these contracts in `client/src/core/platform/types.ts` and keep the
exports re-exported from `client/src/core/platform/index.ts`.

```ts
export type SignerCryptoInvocationErrorCode =
  | 'unavailable'
  | 'worker_transport_failure'
  | 'native_binding_failure'
  | 'timeout';

export type SignerCryptoResult<Ok, CommandCode extends string> =
  | {
      ok: true;
      value: Ok;
      failure?: never;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      failure: 'command';
      code: CommandCode;
      message: string;
      value?: never;
    }
  | {
      ok: false;
      failure: 'invocation';
      code: SignerCryptoInvocationErrorCode;
      message: string;
      value?: never;
    };
```

`AuthenticatorPort` must model PRF as a required branch, not an optional field:

```ts
export type AuthenticatorPrfResult =
  | {
      kind: 'required';
      prfFirstB64u: string;
    }
  | {
      kind: 'available_without_requirement';
      prfFirstB64u: string;
    }
  | {
      kind: 'not_requested_or_unavailable';
      prfFirstB64u?: never;
    };

export type RequiredPrfAuthenticatorSuccess = {
  ok: true;
  requirePrfFirst: true;
  prf: Extract<AuthenticatorPrfResult, { kind: 'required' }>;
};
```

The final code should use the full operation/result union in the
`AuthenticatorPort Contract` section above. The short snippet here documents the
type invariant reviewers should look for: a success result for
`requirePrfFirst: true` cannot omit `prfFirstB64u`.

`ClientSecretSource` must be constructed only through builders:

```ts
export function buildWebAuthnPrfFirstSecretSource(
  input: Extract<AuthenticatorResult, { ok: true; prf: { kind: 'required' } }>,
): WebAuthnPrfFirstSecretSource;

export function buildEmailOtpWorkerSessionSecretSource(
  input: EmailOtpWorkerIssuedSessionHandle,
): EmailOtpWorkerSessionSecretSource;
```

Future branches such as `secure_enclave_wrapped_secret` and `fido2_hmac_secret`
may have builders now, but the browser adapter must return
`unsupported_secret_source` when an active ECDSA bootstrap command receives
them.

Type fixtures to add or update:

- `client/src/core/platform/types.typecheck.ts`: invalid `AuthenticatorPort`
  PRF success branches, incomplete platform runtime, unsupported future secret
  source dispatch, and direct object-literal construction with missing identity
  fields.
- New or existing signer-domain typecheck file: `EcdsaRoleLocalPendingStateBlob`
  cannot be used where `EcdsaRoleLocalReadyStateBlob` is required.
- Existing ECDSA key-domain typecheck file:
  `EcdsaHssClientSharePublicKey33B64u` cannot be supplied as
  `EcdsaClientRootPublicKey33B64u`.

### Typed Durable ECDSA Batch Contract

Replace generic durable-record access for the migrated ECDSA role-local path
with these operation-shaped methods. The browser implementation may delegate to
existing IndexedDB repositories, but core code receives only normalized records
and typed results.

```ts
export type DurableEcdsaRoleLocalStore = {
  loadEcdsaRoleLocalReadyRecord(
    input: LoadEcdsaRoleLocalReadyRecordInput,
  ): Promise<LoadEcdsaRoleLocalReadyRecordResult>;

  persistEcdsaRoleLocalReadyRecord(
    input: PersistEcdsaRoleLocalReadyRecordInput,
  ): Promise<PersistEcdsaRoleLocalReadyRecordResult>;

  cleanupMalformedEcdsaRoleLocalRecord(
    input: CleanupMalformedEcdsaRoleLocalRecordInput,
  ): Promise<CleanupMalformedEcdsaRoleLocalRecordResult>;
};
```

Required input facts:

- `walletId: WalletId`
- `rpId: RpId`
- `chainTarget: ThresholdEcdsaChainTarget`
- `keyHandle: string`
- `ecdsaThresholdKeyId: EcdsaThresholdKeyId`
- `signingRootId: EcdsaHssSigningRootId`
- `signingRootVersion: EcdsaHssSigningRootVersion`
- `participantIds: readonly [1, 2]`

`persistEcdsaRoleLocalReadyRecord(...)` accepts only
`EcdsaRoleLocalReadyRecord`. It rejects pending blobs, raw-share records,
missing relayer public identity, and records whose scalar mirrors disagree with
`publicFacts`.

Candidate implementation targets:

- Browser adapter:
  `client/src/core/platform/browser/createBrowserPlatformRuntime.ts`.
- Existing repository/facade surfaces to delegate through:
  `client/src/core/indexedDB/seamsWalletDB/repositories.ts`,
  `client/src/core/indexedDB/unifiedIndexedDBManager.ts`, and
  ECDSA session persistence helpers under
  `client/src/core/signingEngine/session/persistence/`.

### Phase 2 Browser Adapter Targets

Browser adapter work should be one active ECDSA slice, not a broad platform
rewrite.

Files to change:

- `client/src/core/platform/browser/createBrowserPlatformRuntime.ts`
- `client/src/core/signingEngine/assembly/createPorts.ts`
- `client/src/core/signingEngine/assembly/createManagers.ts`
- `client/src/core/signingEngine/workerManager/SignerWorkerManager.ts`
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
- `client/src/core/types/signer-worker.ts`
- `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`

Adapter rules:

- WebAuthn collection normalizes raw browser credentials inside the browser
  `AuthenticatorPort`.
- The hss-client Worker request/response envelope stays in the browser
  `SignerCryptoPort` implementation.
- Core ECDSA bootstrap code receives only
  `SignerCryptoResult<PrepareEcdsaClientBootstrapOutput, ...>` and
  `SignerCryptoResult<FinalizeEcdsaClientBootstrapOutput, ...>`.
- Worker transport failures map to `failure: 'invocation'`.
- Crypto/protocol validation failures map to `failure: 'command'`.
- Unsupported iOS/Linux secret-source branches map to
  `failure: 'command', code: 'unsupported_secret_source'`.

Acceptance gate:

- A source guard fails if any module under
  `client/src/core/signingEngine/session`, `client/src/core/signingEngine/flows`,
  or `client/src/core/signingEngine/threshold/ecdsa` imports browser Worker
  transport helpers directly after the adapter is wired, except explicitly
  allowlisted browser adapter modules.

### Phase 3 Persistence Contract

The normalized internal record is:

```ts
export type EcdsaRoleLocalReadyRecord = {
  kind: 'ecdsa_role_local_ready_record_v1';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
};
```

The raw boundary record is:

```ts
export type EcdsaRoleLocalRawRecord =
  | {
      kind: 'legacy_raw_role_local_v1';
      clientShare32B64u: string;
      clientPublicKey33B64u: string;
      clientCaitSithInput: {
        mappedPrivateShare32B64u: string;
        verifyingShare33B64u: string;
      };
      publicFacts: EcdsaRoleLocalPublicFacts;
    }
  | {
      kind: 'ready_blob_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
    };
```

Only the parser may accept `EcdsaRoleLocalRawRecord`:

```ts
export function parseRawEcdsaRoleLocalRecord(
  raw: unknown,
): EcdsaRoleLocalRecordParseResult;
```

Parser home:

- Prefer `client/src/core/signingEngine/session/persistence/records.ts` if the
  change stays local.
- Split to a neutral sibling module if `records.ts` becomes harder to review,
  for example
  `client/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`.

Consumers that must move to `EcdsaRoleLocalReadyRecord` only:

- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
- `client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
- `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `client/src/core/rpcClients/relayer/walletRegistration.ts`
- Email OTP ECDSA bootstrap handling in
  `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`

Deletion rule:

- After the in-development data reset, remove
  `legacy_raw_role_local_v1` parsing and all references to raw share fields
  outside tests that assert deletion.

### Phase 4 Prepare/Finalize Mapping

The current helper `buildThresholdEcdsaHssRoleLocalClientBootstrapWasm(...)`
combines prepare-like and ready-state-like data in one return value. Split it
into two transport-free operations.

Prepare maps current fields as follows:

| Current field | New field |
| --- | --- |
| `contextBinding32B64u` | `clientBootstrap.contextBinding32B64u` |
| `clientPublicKey33B64u` | `clientBootstrap.hssClientSharePublicKey33B64u` and `publicFacts.hssClientSharePublicKey33B64u` |
| `clientShareRetryCounter` | `clientBootstrap.clientShareRetryCounter` |
| `clientShare32B64u` | internal pending blob only |
| `mappedPrivateShare32B64u` | internal pending/ready blob only |
| `verifyingShare33B64u` | internal pending/ready blob only or public `clientVerifyingShareB64u` only if still required by relayer protocol |

Finalize consumes:

- `pendingStateBlob`
- normalized relayer public identity from
  `client/src/core/rpcClients/relayer/thresholdEcdsa.ts` or
  `client/src/core/rpcClients/relayer/walletRegistration.ts`
- expected public facts from the prepare context

Finalize returns:

- `stateBlob: EcdsaRoleLocalReadyStateBlob`
- public facts needed by routing, persistence indexes, key refs, and export

The active TypeScript path must stop reconstructing ready role-local state by
spreading or copying helper result fields. The only builder for ready state is
the signer-crypto finalize result plus public-fact parser.

### Phase 5 Secret Source Builders

Source builders must live near the current secret-source boundary:

- `client/src/core/signingEngine/threshold/ecdsa/clientSecretSource.ts`
- or a new neutral module under `client/src/core/platform/secretSources.ts` if
  the platform contract owns all branches.

Required builders:

- `buildWebAuthnPrfFirstSecretSource(...)`
- `buildEmailOtpWorkerSessionSecretSource(...)`
- `buildSecureEnclaveWrappedSecretSource(...)`
- `buildFido2HmacSecretSource(...)`

Rules:

- `buildWebAuthnPrfFirstSecretSource(...)` accepts only a normalized
  authenticator result whose `prf.kind === 'required'`.
- `buildEmailOtpWorkerSessionSecretSource(...)` accepts only an Email OTP
  worker-issued handle already bound to wallet id, provider subject or session
  subject as appropriate, action, operation, and chain target.
- Core ECDSA bootstrap does not accept `clientRootShare32B64u`,
  `clientRootShare32`, or Email OTP root-share bytes after this phase.
- Browser dispatch rejects unsupported future branches with
  `unsupported_secret_source`; core functions do not switch over unsupported
  branches they cannot execute.

### Phase 6 Rust/WASM Command Spec

Rust implementation targets:

- `crates/signer-core`: reusable command implementation, validation, HKDF,
  client-root derivation, additive-share mapping, pending/ready state
  serialization, public fact validation, and error codes.
- `wasm/hss_client_signer`: browser WASM binding that exposes the signer-core
  prepare/finalize commands.

TypeScript replacement targets:

- Replace or wrap
  `buildThresholdEcdsaHssRoleLocalClientBootstrapWasm(...)` with
  `prepareEcdsaClientBootstrap(...)` and `finalizeEcdsaClientBootstrap(...)`.
- Update worker contracts in `client/src/core/types/signer-worker.ts` so active
  success responses no longer return raw private/share fields.
- Update `client/src/core/signingEngine/workerManager/workerTypes.ts` so
  worker-facing operation branches mirror the signer-crypto commands.

Parity fixtures must cover:

- WebAuthn PRF input branch to prepare output.
- Email OTP worker-session input branch to prepare output.
- Relayer public identity input to finalize output.
- Public fact equality across old and new paths while the old path still exists
  in tests.
- Rejection when relayer public identity mismatches pending state.
- Rejection when a client-root proof is verified against an HSS client-share
  public key.

Old TypeScript helper code may remain only in tests for fixture parity while the
new command is being introduced. Delete it from production once parity passes.

### Required Source Guards

Add or extend guard tests so drift is caught mechanically.

1. Platform leakage guard:
   - scan `client/src/core/signingEngine/session`,
     `client/src/core/signingEngine/flows`,
     `client/src/core/signingEngine/threshold`, and
     `client/src/core/signingEngine/interfaces`
   - reject imports or direct references to `IndexedDBManager`,
     `UnifiedIndexedDBManager`, `IDB`, `navigator.credentials`, `Worker`,
     `MessageChannel`, `window`, `document`, `localStorage`, and
     `crypto.subtle`
   - allowlist only browser adapter, UI, and worker implementation files

2. Raw HSS field guard:
   - reject `clientShare32B64u`, `clientAdditiveShare32B64u`,
     `mappedPrivateShare32B64u`, `verifyingShare33B64u`,
     `clientCaitSithInput`, and HSS-meaning `clientPublicKey33B64u` in active
     core modules
   - allowlist persistence boundary parsers, legacy cleanup tests, fixture
     files, and Rust/WASM parity tests until the old path is deleted

3. Secret-source guard:
   - reject `clientRootShare32B64u` and `clientRootShare32` in core ECDSA
     bootstrap call sites after Phase 5
   - allowlist browser adapter internals and signer-core/WASM binding tests

4. Worker transport guard:
   - reject direct hss-client Worker request construction outside
     `createBrowserPlatformRuntime.ts`, worker implementation files, and tests

### Phase Acceptance Tests

Each phase must have a mechanical completion gate:

| Phase | Required tests |
| --- | --- |
| 1.5 contracts | `npx tsc --noEmit -p sdk/tsconfig.build.json`; platform type fixtures; source guards for loose PRF and raw field use. |
| 2 browser adapter | Existing HSS worker surface tests; a unit test proving worker transport errors become invocation errors and crypto validation errors become command errors. |
| 3 persistence | Parser tests for `ready_blob_v1`, malformed raw cleanup, scalar mirror mismatch, and rejection of raw records by core consumers. |
| 4 prepare/finalize | Runtime regression for client-root proof vs HSS share key; type fixture for key-domain mismatch; worker mapping tests for prepare and finalize. |
| 5 secret sources | Type fixtures rejecting missing identity fields and broad branch spreads; unit tests for WebAuthn PRF required branch and Email OTP worker-session branch. |
| 6 Rust/WASM command | `cargo test --manifest-path crates/signer-core/Cargo.toml`; `cargo test --manifest-path wasm/hss_client_signer/Cargo.toml`; parity fixture tests; targeted browser HSS tests. |

### Non-Goals For The MVP Slice

- Do not add public iOS, Linux, React Native, Android, Node-only, or Cloudflare
  Worker SDK APIs.
- Do not migrate Ed25519 persistence unless a shared helper must move to keep
  ECDSA types coherent.
- Do not move UI prompts, iframe routing, React components, browser storage
  schema ownership, retry UX, or relayer HTTP routing into Rust.
- Do not wrap every worker message in `SignerCryptoPort`; wrap only operations
  whose core call sites are migrating.
- Do not keep a production dual path after the ECDSA bootstrap slice lands.

## TODO Checklist

Use this as the concrete execution checklist for the MVP. Keep each item scoped
to a single PR where practical.

### Inventory And Contracts

- [x] Add a checked boundary inventory for direct `IndexedDBManager`,
      `UnifiedIndexedDBManager`, WebAuthn, Worker, `crypto.subtle`, and
      browser-global usage in signing/session paths.
- [x] Add `client/src/core/platform/types.ts` with `PlatformRuntime`,
      `PlatformKind`, `DurableRecordStore`, `AuthenticatorPort`,
      `SignerCryptoPort`, `HttpTransport`, `ClockPort`, and `RandomSource`.
- [x] Add discriminated-union type fixtures for `PlatformKind`,
      `ClientSecretSource`, and `SignerCryptoPort` result branches.
- [x] Add an `assertNever` helper or reuse the existing project helper for
      platform dispatch exhaustiveness.
- [ ] Bring `client/src/core/platform/types.ts` into exact alignment with the
      canonical contract in this document.
- [ ] Add `SignerCryptoResult` with separate command and invocation failure
      branches.
- [ ] Add `finalizeEcdsaClientBootstrap` to the platform signer-crypto contract.
- [ ] Replace optional authenticator PRF result fields with explicit `prf.kind`
      success branches.
- [ ] Replace temporary generic `DurableRecordStore` get/put/delete scaffolding
      with typed repository batch operations for the ECDSA signing-session
      records touched by this refactor.
- [ ] Update `AuthenticatorPort` types to use branch-specific create/get
      passkey outputs with raw verification payloads, PRF material, credential
      identity, and typed cancellation/error codes.

### Browser Platform Adapter

- [x] Add
      `client/src/core/platform/browser/createBrowserPlatformRuntime.ts`.
- [x] Add the initial browser `DurableRecordStore` scaffold over existing
      IndexedDB infrastructure.
- [ ] Wire the browser `DurableRecordStore` to typed ECDSA signing-session
      repository batches instead of generic unavailable get/put/delete methods.
- [ ] Wrap existing WebAuthn credential collection as the browser
      `AuthenticatorPort`.
- [ ] Wrap the ECDSA client-bootstrap hss-client worker dispatch as the first
      browser `SignerCryptoPort` prepare/finalize operation pair.
- [x] Wrap `fetch`, `Date.now`, timers, and WebCrypto randomness behind the
      browser runtime ports where current signing flows need them.
- [x] Update `createSigningEnginePorts(...)` so it receives a browser
      `PlatformRuntime`.
- [x] Remove direct `IndexedDBManager` imports from signing-engine assembly
      files after the platform runtime is wired.
- [ ] Update `SignerWorkerManager` so storage, authenticator, and worker
      transport dependencies are injected through runtime construction.

### ECDSA Secret Source Boundary

- [ ] Promote the existing ECDSA client-secret source helper into the canonical
      `ClientSecretSource` boundary.
- [ ] Add branch-specific builders for `webauthn_prf_first`,
      `email_otp_worker_session`, `secure_enclave_wrapped_secret`, and
      `fido2_hmac_secret`.
- [ ] Add type fixtures rejecting broad spreads and raw-record casts into
      `ClientSecretSource`.
- [ ] Make `email_otp_worker_session` a worker-owned opaque handle and remove
      active core paths that pass Email OTP root-share bytes through TypeScript.
- [ ] Keep iOS and embedded branches as typed unsupported dispatch failures in
      the browser adapter.
- [ ] Move passkey PRF to client-root HKDF derivation behind
      `SignerCryptoPort.prepareEcdsaClientBootstrap`.
- [x] Decision: reusable HKDF and ECDSA bootstrap logic belongs in
      `crates/signer-core`, exposed to the browser through
      `wasm/hss_client_signer`.

### Coarse ECDSA Bootstrap Command

- [x] Add the initial `prepareEcdsaClientBootstrap` shape to
      `SignerCryptoPort`.
- [ ] Add `finalizeEcdsaClientBootstrap` to `SignerCryptoPort`.
- [x] Rename HSS client-share public key fields to
      `hssClientSharePublicKey33B64u`.
- [x] Rename client-root proof verifier fields to
      `clientRootPublicKey33B64u`.
- [x] Add branded key-domain types for client-root, HSS client-share, and
      relayer HSS public keys.
- [x] Make `verifyClientRootProof(...)` accept an `EcdsaClientRootProof` object
      that carries its root verifier key.
- [x] Keep HSS bootstrap identity parsing separate from client-root proof
      parsing, then combine only validated normalized branches.
- [ ] Expand `PrepareEcdsaClientBootstrapInput` to require the full context,
      participant ids, and narrow `ClientSecretSource` branch.
- [ ] Add `FinalizeEcdsaClientBootstrapInput` with pending state blob and
      relayer public identity.
- [ ] Add type fixtures proving ready state blobs cannot be passed to finalize
      and pending state blobs cannot be used by signing/export/key-ref builders.
- [ ] Update the `hssClient` worker request/result contract to expose the new
      coarse prepare/finalize commands.
- [ ] Add the reusable signer-core command for HKDF/client-root derivation,
      additive-share mapping, public fact validation, pending state
      serialization, and ready state finalization.
- [ ] Update `wasm/hss_client_signer` to call signer-core and return public
      facts plus pending and ready blob envelopes.
- [ ] Stop returning `clientShare32B64u`, `mappedPrivateShare32B64u`, and
      `verifyingShare33B64u` to TypeScript from the active bootstrap path.
- [ ] Update `buildThresholdEcdsaHssRoleLocalClientBootstrapWasm(...)` or
      replace it with `prepareEcdsaClientBootstrap(...)` and
      `finalizeEcdsaClientBootstrap(...)` wrappers.
- [ ] Update wallet registration bootstrap and threshold ECDSA session
      bootstrap flows to send prepare output to the relayer, finalize with
      relayer public identity, then persist ready opaque state and public facts.
- [ ] Update the Email OTP worker ECDSA bootstrap path to call the same coarse
      Rust/WASM command shape.

### Persistence And Key Refs

- [ ] Replace `ThresholdEcdsaHssRoleLocalClientState` raw share fields with an
      `EcdsaRoleLocalReadyStateBlob` envelope and required public identity
      fields.
- [ ] Add `EcdsaRoleLocalPublicFacts`, `EcdsaRoleLocalReadyRecord`, and
      `EcdsaRoleLocalRecordParseResult` to the neutral persistence module.
- [ ] Ensure old raw role-local records are read only by the persistence boundary
      parser and all new writes use `ready_blob_v1`.
- [ ] Update `ThresholdEcdsaBackendBinding` so signing material is represented
      by an opaque state blob or typed handle.
- [ ] Scope persistence parser changes to ECDSA HSS role-local session records
      and key-ref builders. Keep unrelated IndexedDB records out of this phase.
- [ ] Update persistence record parsers to normalize old ECDSA raw boundary data
      only at the persistence boundary while this in-development data exists.
- [ ] Update EVM-family key-ref builders to consume the new opaque role-local
      state shape.
- [ ] Remove `clientAdditiveShare32B64u` from active core signing paths after
      the opaque state path is complete.

### Export And Recovery

- [ ] Update ECDSA HSS export to consume the opaque role-local state blob.
- [ ] Stop re-deriving export material from `clientRootShare32B64u` in the
      active export path.
- [ ] Update passkey recovery export flow to collect a `ClientSecretSource`
      only when the platform adapter needs to unlock or refresh state.
- [ ] Update Email OTP recovery/export flow to use worker-owned handles or
      opaque state rather than exposing root-share bytes to core TypeScript.

### Tests And Verification

- [ ] Update parser and guard tests that currently assert raw HSS fields.
- [x] Add a runtime regression test where a client-root proof rejects when
      verified against an HSS client-share public key.
- [x] Add a type fixture rejecting
      `EcdsaHssClientSharePublicKey33B64u` as an
      `EcdsaClientRootPublicKey33B64u` verifier.
- [ ] Add parity fixtures for current WebAuthn PRF inputs, prepare output,
      relayer public identity finalization input, and expected public facts.
- [ ] Add tests proving TypeScript cannot construct invalid
      `ClientSecretSource` branches or incomplete platform runtimes.
- [ ] Add tests proving authenticator success branches cannot omit required PRF
      material.
- [ ] Add persistence tests for the ready opaque role-local state record shape.
- [ ] Add import guards for platform leakage and raw HSS share-field leakage in
      core modules.
- [ ] Add export tests that use opaque state and reject missing public identity.
- [x] Run `npx tsc --noEmit -p sdk/tsconfig.build.json`.
- [x] Run targeted ECDSA HSS unit tests.
- [ ] Run relevant `cargo test` commands for the Rust crate/WASM package touched
      by the coarse command.
- [ ] Record before/after browser JS, WASM, and lazy-flow asset sizes.

### Deferred Follow-Ups

- [ ] Evaluate moving one deterministic state machine into
      `crates/signer-core` after the coarse ECDSA bootstrap command lands.
- [ ] Define the first real `crates/signer-platform-ios` API around the same
      `SignerCryptoPort` command.
- [ ] Define the Linux/embedded binding shape: native crate, C ABI, or local
      daemon.
- [ ] Add Verus or LEAN-facing invariants only after the Rust state-machine or
      protocol boundary has stabilized.

## Verification Matrix

Run the smallest row that covers the touched phase. Add the next broader row
when a change crosses persistence, crypto, or exported SDK boundaries.

| Change area | Required checks |
| --- | --- |
| Platform type contracts only | `npx tsc --noEmit -p sdk/tsconfig.build.json` |
| Import guards or raw-field guard changes | `pnpm -C tests exec playwright test ./unit/signerDomain.guard.unit.test.ts ./unit/signer-worker.guards.test.ts --reporter=line` |
| Authenticator or secret-source builders | `npx tsc --noEmit -p sdk/tsconfig.build.json`; `pnpm -C tests exec playwright test ./unit/webauthnPromptCredentialSelection.unit.test.ts ./unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts --reporter=line` |
| ECDSA HSS worker adapter or WASM surface | `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts ./unit/thresholdEcdsa.hssErrorCodes.unit.test.ts --reporter=line` |
| ECDSA role-local persistence parser | `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts ./unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts --reporter=line` |
| ECDSA export/recovery path | `pnpm -C tests exec playwright test ./unit/ecdsaExportMaterial.unit.test.ts ./unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts ./unit/passkeyConfirm.exportFlow.unit.test.ts --reporter=line` |
| Rust signer-core command | `cargo test --manifest-path crates/signer-core/Cargo.toml` |
| Browser WASM binding for signer-core command | `cargo test --manifest-path wasm/hss_client_signer/Cargo.toml`; `pnpm -C tests exec playwright test ./unit/thresholdEcdsa.hssWasmSurface.unit.test.ts --reporter=line` |
| Cross-platform parity fixture | `pnpm -C tests run test:signer-parity:rust` |
| Public SDK or broad flow behavior | `pnpm -C tests run test:unit`; add targeted e2e only when registration, unlock, export, or signing UX changes |
| Bundle-size-sensitive WASM change | record before/after JS, WASM, and lazy-flow asset sizes in the PR description |

## Risks

1. Over-abstracting before another platform exists.
   Keep ports narrow and based on active browser call sites.

2. Carrying duplicate browser and neutral paths.
   End each phase by deleting the replaced browser-specific path from core
   modules.

3. Moving orchestration into Rust too early.
   Keep UI, prompts, browser storage, retry policy, and network orchestration in
   platform adapters. Move crypto-internal assembly and pure state machines only
   when the boundary becomes simpler.

4. Weak boundary parsing.
   Raw platform records, request bodies, worker responses, and credential
   results must normalize once at the boundary.

5. Package-size regression.
   Measure WASM artifacts after any new coarse Rust/WASM command used by the
   browser SDK.

## Refactor Guardrails

- Do not add legacy flags or compatibility paths inside core logic.
- Do not introduce broad optional bags for auth, identity, session, signing,
  restore, export, or lifecycle state.
- Do not pass raw IndexedDB records, raw WebAuthn credentials, raw worker
  payloads, or raw native binding payloads into core modules.
- Do not keep both TypeScript helper pipelines and coarse Rust/WASM commands
  active after a slice lands.
- Do not make iOS or embedded SDK public APIs in this refactor.
- Do not move React, iframe UI, browser prompt UX, or DOM code into Rust.

## Completion Definition

This refactor is complete when:

- The signing runtime is constructed from a `PlatformRuntime`.
- Browser APIs are isolated to browser adapters and UI/browser folders.
- Core signing/session modules consume normalized records and strict secret
  source branches.
- Signer crypto operations can be implemented by a browser Worker, direct WASM
  call, native binding, or local service through the same command port.
- At least one crypto-boundary slice has been internalized behind a coarse
  Rust/WASM signer command with parity coverage.
- Existing browser registration, signing, recovery, HSS rebuild, and export
  flows remain green.

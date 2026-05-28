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
      prfFirstB64u: string;
    }
  | {
      ok: true;
      operation: 'create_passkey';
      requirePrfFirst: false;
      credential: WebAuthnRegistrationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prfFirstB64u?: string;
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: true;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prfFirstB64u: string;
    }
  | {
      ok: true;
      operation: 'get_passkey';
      requirePrfFirst: false;
      credential: WebAuthnAuthenticationCredential;
      credentialIdB64u: string;
      rawIdB64u: string;
      prfFirstB64u?: string;
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
`prfFirstB64u`; missing PRF output is a `prf_unavailable` failure.

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
    clientPublicKey33B64u: string;
    clientShareRetryCounter: number;
    participantId: 1;
  };
  publicFacts: {
    clientPublicKey33B64u: string;
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
    clientPublicKey33B64u: string;
    clientVerifyingShareB64u: string;
    relayerPublicKey33B64u: string;
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

type PrepareEcdsaClientBootstrapErrorCode =
  | 'unsupported_secret_source'
  | 'invalid_secret_source'
  | 'invalid_context'
  | 'invalid_threshold_parameters'
  | 'invalid_public_material'
  | 'crypto_failure'
  | 'worker_transport_failure';

type FinalizeEcdsaClientBootstrapErrorCode =
  | 'invalid_pending_state'
  | 'invalid_relayer_public_identity'
  | 'public_identity_mismatch'
  | 'crypto_failure'
  | 'worker_transport_failure';
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
- Run the cheapest affected unit tests for signing-engine assembly and worker
  dispatch.

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

Tasks:

- [ ] Define the `prepareEcdsaClientBootstrap` and
      `finalizeEcdsaClientBootstrap` signer-crypto operations
      independent of Web Worker transport.
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
3. Phase 2: browser runtime adapter for the ECDSA bootstrap slice. Finish typed
   ECDSA repository batches, browser WebAuthn collection, and the browser
   bootstrap prepare/finalize worker adapter.
4. Phase 3: narrow ECDSA persistence record split. Move only ECDSA HSS
   role-local records and key-ref builders onto normalized boundary parsers.
5. Phase 4: signer operation versus transport split for
   `prepareEcdsaClientBootstrap` and `finalizeEcdsaClientBootstrap`. This phase
   defines the operation shapes and maps the current hss-client Worker
   request/response into a transport-free crypto port.
6. Phase 5: platform-neutral ECDSA secret sources. Tighten
   `webauthn_prf_first` and `email_otp_worker_session` branches before moving
   active bootstrap call sites.
7. Phase 6: signer-core/WASM coarse ECDSA bootstrap command. Implement HKDF,
   share mapping, validation, pending state serialization, and ready state
   finalization in
   `crates/signer-core`, then expose the command through
   `wasm/hss_client_signer`.
8. Phase 7: optional portable state-machine pilot after the coarse command is
   active and stable.
9. Phase 8: native binding hardening after signer-core vectors exist.

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
- [ ] Expand `PrepareEcdsaClientBootstrapInput` to require the full context,
      participant ids, and narrow `ClientSecretSource` branch.
- [ ] Add `FinalizeEcdsaClientBootstrapInput` with pending state blob and
      relayer public identity.
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
- [ ] Add parity fixtures for current WebAuthn PRF inputs, prepare output,
      relayer public identity finalization input, and expected public facts.
- [ ] Add tests proving TypeScript cannot construct invalid
      `ClientSecretSource` branches or incomplete platform runtimes.
- [ ] Add persistence tests for the ready opaque role-local state record shape.
- [ ] Add export tests that use opaque state and reject missing public identity.
- [x] Run `npx tsc --noEmit -p sdk/tsconfig.build.json`.
- [ ] Run targeted ECDSA HSS unit tests.
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

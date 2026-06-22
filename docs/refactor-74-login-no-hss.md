# Refactor 74: Normal Wallet Operations Without Ed25519 HSS

Date created: June 19, 2026

Status: complete for required no-HSS unlock/signing scope; optional background
restore remains deferred.

Primary source of truth:

- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [refactor-69C-cleanup-reduce-bloat.md](./refactor-69C-cleanup-reduce-bloat.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Goal

Make wallet unlock and ordinary Ed25519 transaction signing run without any
Ed25519 HSS key-derivation ceremony.

Warm signing session means:

- Wallet Session JWT exists.
- Signing grant id exists.
- Threshold session id exists.
- Expiry and budget are active.
- credential-scoped unseal authorization may exist as a short-lived worker
  handle for passkey PRF or recovery-code restore.
- Signing root, lane, and worker scope are persisted.

Ed25519 client signing material is a separate lifecycle. The HSS ceremony should
run only when a flow intentionally derives or exports key material:

- registration material setup
- add-signer or device-sync material setup
- explicit key export

Normal wallet unlock, warm-session restore, and daily transaction signing should
never invoke HSS. Those flows should use an existing client MPC share held by the
signer-core/WASM worker or restored from a worker-owned sealed artifact.

## Current Problem

`SeamsWeb.login().unlock()` currently does more than unlock the wallet. With the
default signing session policy, it also tries to make signing lanes immediately
ready.

The current critical path is:

```text
unlock()
  -> mint or restore Wallet Session
  -> warm threshold signing sessions
  -> prewarmThresholdEd25519ClientBaseFromCredential()
  -> run Ed25519 HSS material-handle reconstruction
  -> assert ready signing lanes
  -> return unlock success
```

This makes wallet unlock pay the Ed25519 HSS cost even when the caller only
needs an authenticated wallet session.

The same architectural problem exists in the first normal signing operation
after a worker restart. Current transaction signing can treat an Ed25519 warm
session as sign-plannable while material is pending, then call
`ensureThresholdEd25519HssSigningMaterial()` to reconstruct material through HSS
before Router A/B normal signing. That is the fallback this refactor removes
from normal signing.

Key files:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`

## Verified Current Code Shape

The current code already separates authorization from material enough to skip
HSS during unlock. It does not yet satisfy the stronger target that daily
signing never invokes HSS.

Verified unlock-side callchain:

```text
login.ts
  -> warmThresholdSigningSessions()
  -> primeThresholdLoginWarmSigners()
  -> signingEngine.connectEd25519Session()
  -> provisionThresholdEd25519Session()
  -> threshold/ed25519/connectSession.connectEd25519Session()
  -> mintEd25519WalletSession()
  -> persistWarmSessionEd25519Capability()
  -> cacheSigningSessionPrfFirst()
```

This callchain mints the Wallet Session JWT, persists the warm Ed25519 record,
and caches PRF.first for later material repair. It does not need Ed25519 HSS.
The HSS ceremony enters only through the extra unlock-side call to
`prewarmThresholdEd25519ClientBaseFromCredential()`.

Verified transaction-signing callchain:

```text
signTransactions()
  -> resolveNearSigningSessionAuthContext()
  -> deriveEd25519CapabilityState()
  -> requireNearStepUpAuth()
  -> buildNearEd25519StepUpAuthorization()
  -> resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp()
  -> requireOrRestoreRouterAbEd25519WalletSessionState()
  -> RestoreThresholdEd25519WorkerMaterial when the record is restore_available
  -> persistStoredThresholdEd25519SessionMaterialHandle()
  -> resolveRouterAbEd25519WalletSessionStateFromRecord()
  -> requireRouterAbEd25519NormalSigningReadyState()
  -> Router A/B Ed25519 normal-signing prepare/finalize
```

That means the transaction path can hydrate material after unlock and before any
signature is produced. Today that hydration can invoke HSS. The target refactor
must replace that fallback with signer-core material restore or a clear
`material_restore_required` failure. `requireRouterAbEd25519NormalSigningReadyState()`
still correctly requires a material handle, material binding digest, client
verifier, Wallet Session JWT, signing-root scope, and SigningWorker scope before
Router A/B signing starts.

Verified registration persistence gap:

```text
registration.ts
  -> prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst()
  -> startWalletRegistration()
  -> prepareThresholdEd25519RegistrationHssClientRequest()
  -> respondWalletRegistrationHss()
  -> buildThresholdEd25519RegistrationHssClientOwnedArtifact()
  -> finalizeWalletRegistration()
  -> storeWalletEd25519RegistrationData()
  -> keyMaterialForSignerActivation()
```

The registration path uses HSS and obtains the Ed25519 key material, then the
local persistence layer stores threshold public metadata such as public key,
relayer key id, key version, and participant ids. It does not persist a
signer-core-owned client MPC share artifact that the normal signing worker can
restore later. That is why normal signing currently has to reconstruct client
material when the worker handle is missing.

### Verified No-HSS Cases

The current code can avoid an HSS ceremony in these cases:

- Unlock: after removing `prewarmThresholdEd25519ClientBaseFromCredential()`,
  the unlock path mints/restores authorization only.
- Signing with a loaded material handle:
  `requireThresholdEd25519WorkerMaterialHandle()` calls
  `validateThresholdEd25519WorkerMaterialNearSignerWasm()` when the record already has
  handle metadata. If that worker handle validates, no HSS ceremony runs.

The current code restores no-HSS first-sign material through
`RestoreThresholdEd25519WorkerMaterial` when the record has a sealed worker
material artifact and a credential-scoped unseal authorization. Raw client-base
material stays inside signer-core/WASM worker memory or a worker-owned sealed
restore artifact.
TypeScript should route opaque handles and metadata only.

## Signer-Core Crypto Boundary

Cryptographic operations and cryptographic material belong in the Rust
`signer-core` crate and the browser WASM workers that wrap it.

TypeScript may own:

- lifecycle state
- domain parsing at SDK/persistence/request boundaries
- Wallet Session JWT transport
- policy, budget, lane, and signing-root metadata
- opaque material handles
- material/session binding digests and public verifier facts
- worker command orchestration

TypeScript must not own:

- raw Ed25519 client base material
- HSS private/evaluator material
- PRF-derived signing material
- signing-share generation
- Ed25519 signing key reconstruction
- material cache validation implemented in JavaScript

## Intended Architecture

The no-HSS design has three layers with separate authority:

1. `crates/signer-core` owns Ed25519 material command types, material/session
   binding digest construction, sealed material blob parsing, material
   encryption/decryption, verifying-share checks, and FROST signing-share
   construction.
2. `wasm/near_signer` owns the browser worker command enum, the WASM message
   handlers, and the in-memory material registry used by NEAR transaction,
   NEP-413, and delegate signing.
3. `packages/sdk-web` owns lifecycle state, route orchestration, IndexedDB or
   secure worker storage references, Wallet Session JWT transport, and public
   binding metadata.

The existing code already shows the needed insertion points:

- `packages/sdk-web/src/core/types/signer-worker.ts` defines custom near signer
  material requests that currently include raw `xClientBaseB64u`.
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
  currently keeps `thresholdEd25519HssMaterialByHandle` as a TypeScript map
  containing raw `xClientBaseB64u`.
- `wasm/near_signer/src/threshold/threshold_hss.rs` currently opens the masked
  HSS client output and returns `x_client_base_b64u` to TypeScript.
- `wasm/near_signer/src/threshold/threshold_frost.rs` currently builds client
  FROST commitments and signature shares from raw `x_client_base_b64u`.
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  currently persists optional `xClientBaseB64u` and material-handle metadata.

The target architecture deletes the TypeScript raw-material map. The WASM layer
keeps a Rust-owned material registry keyed by an opaque material handle. TypeScript
can ask the worker to validate, restore, or use a handle, and the worker returns
only public verifier facts and opaque handles.

The sealed client MPC share is durable key material. It is bound to stable key
identity only. Warm Wallet Sessions, signing grants, budget state, worker
routing, and expiry are per-session activation facts layered on top of that
durable artifact. A normal unlock refreshes activation. Registration,
add-signer, device-sync, and explicit repair create or replace durable material.

### Material Lifecycle

Ed25519 signing material has three explicit states:

```ts
type Ed25519WorkerMaterialUnavailable = {
  kind: 'ed25519_worker_material_unavailable_v1';
  reason:
    | 'missing_sealed_artifact'
    | 'missing_unseal_authorization'
    | 'invalid_binding'
    | 'expired'
    | 'corrupt';
};

type Ed25519WorkerMaterialRestoreAvailable =
  | {
      kind: 'ed25519_worker_material_restore_available_with_handle_v1';
      materialHandle: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      sealedWorkerMaterialRef: string;
      materialFormatVersion: 'ed25519_worker_material_v1';
      xClientBaseB64u?: never;
    }
  | {
      kind: 'ed25519_worker_material_restore_available_sealed_only_v1';
      materialHandle?: never;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      sealedWorkerMaterialRef: string;
      materialFormatVersion: 'ed25519_worker_material_v1';
      xClientBaseB64u?: never;
    };

type Ed25519WorkerMaterialLoaded = {
  kind: 'ed25519_worker_material_loaded_v1';
  materialHandle: string;
  materialBindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterialRef: string;
  xClientBaseB64u?: never;
};
```

`materialHandle` is a loaded-worker handle. It may be persisted as a hint, but
validation must always ask the worker. `sealedWorkerMaterialRef` is the durable
restore capability for the client MPC share. A record with a stale loaded handle
and a valid sealed ref must restore through the worker. A record without a
sealed ref returns `material_restore_required`.

### Worker Material Binding

Worker material has two bindings:

- durable material binding: stable facts that identify the client MPC share
- session activation binding: short-lived facts that authorize one warm signing
  session to use an already stored or restored share

The durable material binding digest is the SHA-256 base64url digest of
canonical JSON:

```ts
type Ed25519WorkerMaterialKeyIdentityV1 = {
  kind: 'ed25519_worker_material_key_identity_v1';
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  keyVersion: string;
  materialFormatVersion: 'ed25519_worker_material_v1';
};

type Ed25519WorkerMaterialBindingV1 = {
  kind: 'ed25519_worker_material_binding_v1';
  curve: 'ed25519';
  protocol: 'router_ab_normal_signing';
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: readonly number[];
  clientVerifyingShareB64u: string;
  materialFormatVersion: 'ed25519_worker_material_v1';
  materialKeyId: string;
  createdAtMs: number;
};
```

`materialKeyId` is:

```text
base64url(SHA-256(canonical_json(Ed25519WorkerMaterialKeyIdentityV1)))
```

This makes the durable material id stable across warm sessions while keeping it
scoped to the selected account signer, signing root, relayer key, and key
version. It must not include `thresholdSessionId`, `signingGrantId`,
`expiresAtMs`, `createdAtMs`, or server budget fields.

`materialKeyId` is stable key identity. `materialBindingDigest` is sealed
artifact identity. The binding digest includes `materialKeyId`, the client
verifying share, participant ids, material format, and `createdAtMs`, so a
reseal or credential rotation may create a new `materialBindingDigest` and
sealed artifact ref while preserving the same `materialKeyId`. A signer-slot,
relayer-key, signing-root, or key-version replacement creates a new
`materialKeyId`.

`signerSlot` and `keyVersion` are required because existing Ed25519 key
inventory is keyed by account signer slot and registration persists relayer key
version metadata. Omitting them risks colliding multiple durable signers for the
same account.

The per-session activation binding is separate:

```ts
type Ed25519WorkerMaterialSessionBindingV1 = {
  kind: 'ed25519_worker_material_session_binding_v1';
  materialBindingDigest: string;
  nearAccountId: string;
  signerSlot: number;
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: readonly number[];
  signingWorkerId: string;
  expiresAtMs: number;
};
```

The durable digest replaces ad hoc material-handle validation. The session
binding proves the current Wallet Session is allowed to use that durable share.
The worker recomputes both bindings during store, restore, validation, and
signing. Mismatched account, root, relayer key, participant ids, verifier,
material id, session id, grant id, worker id, or expiry fails closed before a
FROST commitment or signature-share protocol message is produced.

Canonical JSON v1 is the same representation currently used by
`alphabetizeStringify()`:

- object keys sorted lexicographically at every object level
- array order preserved
- `JSON.stringify()` scalar encoding
- no `undefined`, `null`, optional, or compatibility fields in core binding
  objects
- all strings trimmed and non-empty before canonicalization
- all numbers safe integers; timestamps are Unix milliseconds
- participant ids normalized to ascending unique safe integers before binding
- base64url digests are unpadded

Rust canonicalization must match this byte-for-byte. Add cross-language vectors
before generated TypeScript command types are consumed by SDK code.

### Sealed Artifact Format

The durable artifact is opaque to TypeScript:

```ts
type Ed25519SealedWorkerMaterialV1 = {
  kind: 'ed25519_sealed_worker_material_v1';
  materialFormatVersion: 'ed25519_worker_material_v1';
  materialBindingDigest: string;
  binding: Ed25519WorkerMaterialBindingV1;
  sealedMaterialB64u: string;
  aead: {
    algorithm: 'chacha20poly1305';
    nonceB64u: string;
  };
  kdf: {
    algorithm: 'hkdf_sha256';
    saltB64u: string;
    info: 'seams-ed25519-worker-material-v1';
  };
};
```

Sealing primitive decision: use `ChaCha20Poly1305` with a 96-bit nonce. This
matches the existing Rust dependency already used by signer-core, near-signer,
Ed25519 HSS transport encryption, and email recovery. It keeps the WASM
dependency surface small and avoids the extra nonce/key-derivation work of an
XChaCha variant. The implementation must use the AEAD `Payload` API so the
binding metadata is authenticated as AAD.

The plaintext is a signer-core-owned binary encoding containing the Ed25519
client MPC share needed for role-separated normal signing. Plaintext layout is
defined in Rust, covered by native vectors, and never serialized through
TypeScript objects.

The seal key is derived inside signer-core/WASM:

```text
seal_key = HKDF-SHA256(unseal_secret, salt, "seams-ed25519-worker-material-v1")
```

`nonceB64u` is 12 random bytes generated inside the worker. AEAD associated data
is the UTF-8 canonical JSON encoding of:

```ts
type Ed25519SealedWorkerMaterialAadV1 = {
  kind: 'ed25519_sealed_worker_material_aad_v1';
  materialFormatVersion: 'ed25519_worker_material_v1';
  materialBindingDigest: string;
  binding: Ed25519WorkerMaterialBindingV1;
  aeadAlgorithm: 'chacha20poly1305';
  kdfAlgorithm: 'hkdf_sha256';
  kdfInfo: 'seams-ed25519-worker-material-v1';
};
```

Rust tests must include vectors for digest construction, seal/open roundtrip,
wrong AAD, wrong unseal secret, wrong binding, corrupt ciphertext, and wrong
nonce length.

The sealed artifact transport is also explicit:

```ts
type Ed25519SealedWorkerMaterialTransport =
  | {
      kind: 'storage_ref';
      sealedWorkerMaterialRef: string;
    }
  | {
      kind: 'inline_sealed_blob';
      sealedWorkerMaterialRef: string;
      sealedWorkerMaterialB64u: string;
    };
```

The preferred browser path is `storage_ref` when the worker can resolve the blob
from worker-owned storage. `inline_sealed_blob` is allowed only for opaque
ciphertext copied from an SDK persistence boundary into the worker request.
TypeScript must parse only the outer transport branch and must not parse the
sealed artifact plaintext.

Credential authorization is represented as a worker-local handle. The same
credential class can authorize initial sealing during setup and unsealing during
restore, but each handle has one explicit purpose:

```ts
type Ed25519WorkerMaterialCredentialAuthorizationPurpose = 'seal' | 'unseal';

type Ed25519WorkerMaterialCredentialAuthorization =
  | {
      kind: 'passkey_prf_material_authorization_handle_v1';
      handle: string;
      purpose: Ed25519WorkerMaterialCredentialAuthorizationPurpose;
      rpId: string;
      credentialIdB64u: string;
      materialBindingDigest: string;
      expiresAtMs: number;
    }
  | {
      kind: 'recovery_code_material_authorization_handle_v1';
      handle: string;
      purpose: Ed25519WorkerMaterialCredentialAuthorizationPurpose;
      authSubjectId: string;
      recoveryCodeBindingDigest: string;
      materialBindingDigest: string;
      expiresAtMs: number;
    };

type Ed25519WorkerMaterialSealAuthorization = Ed25519WorkerMaterialCredentialAuthorization & {
  purpose: 'seal';
};

type Ed25519WorkerMaterialUnsealAuthorization = Ed25519WorkerMaterialCredentialAuthorization & {
  purpose: 'unseal';
};
```

TypeScript transports only the handle and public identity facts. The
near-signer worker owns the handle registry. The passkey-confirm or
recovery-confirm boundary may initiate handle issuance, but it must not own a
durable authorization handle, cache secret bytes, or return secret bytes to
core SDK state. For passkey accounts, the secret input is the WebAuthn PRF
output. For email accounts, the secret input is recovery-code-derived material
after email OTP or equivalent account auth has authorized the recovery-code
claim. Email OTP proves account control for the flow; it is not the sealing
secret for durable MPC material.

No TypeScript API may return PRF.first bytes, recovery-code-derived seal bytes,
or any derived seal/unseal key. Pre-store `seal` handles are scoped to one
stable `materialKeyId`, one purpose, one credential source, and one expiry.
Post-store `unseal` handles are scoped to one durable `materialBindingDigest`,
one purpose, one credential source, and one expiry. Use counts are
worker-authoritative and are not trusted from caller-provided metadata. A
`seal` handle cannot restore material, and an `unseal` handle cannot create or
replace a durable sealed artifact. Missing, expired, exhausted,
purpose-mismatched, key-mismatched, or digest-mismatched handles return
`material_unseal_authorization_required` for restore requests and
`material_seal_authorization_required` for setup requests. This path does not
trigger HSS.

Secret-bearing authorization request objects may be constructed only by
credential-confirm boundary adapters that are already holding fresh WebAuthn PRF
bytes or recovery-code material. Core SDK session code, route clients,
persistence mappers, warm-session read models, and signing flows must never
construct `Ed25519PrepareWorkerMaterial*AuthorizationRequest` or
the lower-level private install request values with `prfFirstBytes` or
`recoveryCodeSecret32`.

Error names stay domain-separated. Warm-session authorization state uses
`unseal_authorization_required` to mean the wallet/session is valid but no live
worker unseal capability is available. Worker material restore and signing
return `material_unseal_authorization_required` when a concrete sealed material
operation needs that capability. Boundary mappers may translate between these
domains, but code must not collapse them into a single loose string.

Policy authority stays server-side. The server policy engine owns signing-root
scope, Wallet Session issuance, Signing Grant issuance, server-authoritative
remaining signature budget, transaction policy checks, step-up requirements,
and Router A/B prepare/finalize authorization. The local material authorization
handle is only a cryptographic capability to seal or unseal one worker-owned
MPC artifact. Setup consumes a `materialKeyId`-scoped seal capability before
the final artifact digest exists; restore consumes a `materialBindingDigest`-
scoped unseal capability after the durable artifact exists.

A live `seal` or `unseal` handle cannot authorize signing on its own. Signing
still requires the server-issued Wallet Session, Signing Grant, active budget,
route authorization, and session binding. The worker may apply stricter local
capability limits such as one-use consumption, a short TTL, digest scope, and
purpose scope. Those limits narrow an already server-authorized flow; they do
not replace or expand server policy.

Credential-boundary adapters may ask the worker to issue a material
authorization handle only while handling a server-authorized setup, repair, or
step-up context. For normal signing, the server remains the policy decision
point and the worker handle remains the local material-unseal prerequisite.

Handle creation is a boundary operation:

1. The passkey or recovery-confirm worker receives fresh auth material from the
   browser/WebAuthn or recovery-code boundary.
2. That boundary calls signer-core/WASM immediately to install an
   authorization for one purpose. Setup calls the prepared seal issuer for one
   `materialKeyId`; restore calls the prepared unseal issuer for one
   `materialBindingDigest`.
3. signer-core/WASM derives and stores the seal key or stores the minimum
   secret input needed to derive it. Setup seal handles are scoped by
   `materialKeyId`; restore unseal handles are scoped by
   `materialBindingDigest`.
4. The worker zeroizes any transient JS `Uint8Array` view it had to receive at
   the browser boundary.
5. The worker returns only the opaque credential authorization handle and public
   identity facts.

### Final Credential-Boundary Issuer Architecture

The previous bridge that derived `clientVerifyingShareB64u` in SDK TypeScript
before installing a `seal` handle was transitional. The clean final setup shape
uses a pre-HSS prepared seal issuer scoped to stable material identity, then
lets the store command compute the final verifier and durable artifact digest
after it opens the HSS output inside signer-core/WASM:

1. The credential boundary receives fresh passkey PRF bytes or recovery-code
   material bytes.
2. It transfers those bytes exactly once to a near-signer/signer-core WASM
   issuer command. The transfer may pass through a TypeScript boundary adapter,
   but the adapter must not stringify, persist, log, compare, store, or expose
   the bytes. The adapter zeroizes its transient `Uint8Array` view immediately
   after the worker call settles.
3. signer-core/WASM canonicalizes the public key identity facts, computes the
   stable `materialKeyId`, installs a one-use `seal` authorization handle scoped
   to that `materialKeyId`, and returns only the key id plus the opaque handle.
4. `StoreThresholdEd25519WorkerMaterialFromHssOutput` receives the same public
   identity facts and the `sealAuthorization`. When it opens the HSS output, it
   derives the final `clientVerifyingShareB64u`, builds
   `Ed25519WorkerMaterialBindingV1`, computes `materialBindingDigest`, verifies
   that the binding's `materialKeyId` matches the prepared seal handle, and
   then stores/seals the worker material.
5. If the HSS-opened verifier, material key id, credential-source purpose, or
   handle scope does not match, store fails closed with
   `material_binding_mismatch` or `material_seal_authorization_required`.

The final seal issuer command shape is:

```ts
type Ed25519WorkerMaterialBindingInputWithoutVerifier = {
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: number[];
  createdAtMs: number;
};

type Ed25519PrepareWorkerMaterialSealAuthorizationRequest =
  | {
      kind: 'passkey_prf_seal_authorization_v1';
      bindingInput: Ed25519WorkerMaterialBindingInputWithoutVerifier;
      rpId: string;
      credentialIdB64u: string;
      prfFirstBytes: Uint8Array;
      expiresAtMs: number;
    }
  | {
      kind: 'recovery_code_seal_authorization_v1';
      bindingInput: Ed25519WorkerMaterialBindingInputWithoutVerifier;
      authSubjectId: string;
      recoveryCodeBindingDigest: string;
      recoveryCodeSecret32: Uint8Array;
      expiresAtMs: number;
    };

type Ed25519PreparedWorkerMaterialSealAuthorization = {
  ok: true;
  materialKeyId: string;
  sealAuthorization: Ed25519WorkerMaterialSealAuthorization;
};
```

The final unseal issuer command shape is:

```ts
type Ed25519PrepareWorkerMaterialUnsealAuthorizationRequest =
  | {
      kind: 'passkey_prf_unseal_authorization_v1';
      materialBindingDigest: string;
      rpId: string;
      credentialIdB64u: string;
      prfFirstBytes: Uint8Array;
      expiresAtMs: number;
    }
  | {
      kind: 'recovery_code_unseal_authorization_v1';
      materialBindingDigest: string;
      authSubjectId: string;
      recoveryCodeBindingDigest: string;
      recoveryCodeSecret32: Uint8Array;
      expiresAtMs: number;
    };

type Ed25519PreparedWorkerMaterialUnsealAuthorization = {
  ok: true;
  unsealAuthorization: Ed25519WorkerMaterialUnsealAuthorization;
};
```

Issuer invariants:

- `seal` and `unseal` authorizations are separate commands and separate
  discriminated-union branches.
- `seal` handles are scoped to stable `materialKeyId` because the final
  `materialBindingDigest` depends on the HSS-opened
  `clientVerifyingShareB64u` and does not exist before store.
- Store must recompute the final `materialKeyId` after opening HSS output and
  consume the prepared seal handle only when that id matches exactly.
- `unseal` handles are scoped to `materialBindingDigest` because restore starts
  from an existing durable sealed artifact.
- `seal` handles are one-use in v1. They may expire no later than the
  setup/session expiry. The default TTL is 60 seconds and the hard cap is 5
  minutes unless a future server-authorized capability branch explicitly permits
  a longer lifetime.
- `unseal` handles are one-use by default in v1. They may expire no later than
  the Wallet Session expiry. The default TTL is 60 seconds and the hard cap is
  5 minutes unless a future server-authorized capability branch explicitly
  permits a longer lifetime.
- If a lower-level install command accepts `maxUses`, the worker clamps or
  rejects it. Current `seal` and `unseal` branches accept only `maxUses: 1`;
  any multi-use behavior requires a new server-authorized capability branch,
  tests, and source guards.
- `materialBindingDigest` is computed only from public material binding facts.
  It never includes PRF bytes, recovery-code material, HSS output masks, or raw
  MPC shares.
- The final SDK surface must not expose `deriveThresholdEd25519ClientVerifyingShareFromPrfFirst()`
  as a core-material setup dependency. Verifier derivation for setup happens in
  `StoreThresholdEd25519WorkerMaterialFromHssOutput` after signer-core/WASM
  opens the HSS output. Verifier derivation for display or diagnostics, if
  retained, must be public-only and must not consume raw PRF strings from core
  signing flows.
- The final SDK surface must not expose `prfFirstB64u` for Ed25519 material
  setup, restore, warm-session hydration, or signing. Boundary APIs use
  `Uint8Array` secret inputs and return only authorization handles plus public
  facts.

Private install helpers use this shape inside signer-core/WASM. They are not
SDK worker operations, and their secret byte fields must never be stringified,
persisted, logged, or forwarded to route clients. SDK setup, restore, unlock,
and signing code may only call the prepared issuer commands and receive the
returned opaque authorization handle plus public identity facts:

```ts
type Ed25519InstallPasskeyPrfMaterialAuthorizationRequest = {
  kind: 'ed25519_install_passkey_prf_material_authorization_v1';
  purpose: 'unseal';
  materialBindingDigest: string;
  rpId: string;
  credentialIdB64u: string;
  prfFirstBytes: Uint8Array;
  expiresAtMs: number;
  maxUses: number;
};

type Ed25519InstallRecoveryCodeMaterialAuthorizationRequest = {
  kind: 'ed25519_install_recovery_code_material_authorization_v1';
  purpose: 'unseal';
  materialBindingDigest: string;
  authSubjectId: string;
  recoveryCodeBindingDigest: string;
  recoveryCodeSecret32: Uint8Array;
  expiresAtMs: number;
  maxUses: number;
};

type Ed25519InstallMaterialAuthorizationResult = {
  ok: true;
  authorization: Ed25519WorkerMaterialCredentialAuthorization;
  remainingUses: number;
};
```

After Phase 1C, these install commands are lower-level signer-core/WASM
implementation details. SDK setup, restore, unlock, and signing flows call the
prepared seal/unseal issuer commands. Seal preparation computes only the stable
material key identity plus the credential authorization handle; store computes
the final material binding and artifact digest after opening HSS output. Unseal
preparation starts from an existing material binding digest.

`prfFirstBytes` is the WebAuthn PRF output. `recoveryCodeSecret32` is the
existing recovery-code-derived 32-byte secret produced by the recovery/email
worker after account-control auth. If that worker currently exposes the value as
`prfFirstB64u`, implementation must first move the derivation and handle install
behind the worker boundary and rename the value to recovery-code material. Do
not pass OTP text, recovery-code text, or base64url secret strings through core
SDK TypeScript.

This is the only allowed PRF/recovery-code secret boundary. Core SDK
TypeScript, persistence records, route clients, warm-session state, and signing
flows must never receive, log, compare, or persist PRF.first bytes,
recovery-code-derived seal bytes, or derived seal/unseal keys.

`StoreThresholdEd25519WorkerMaterialFromHssOutput` and
`RestoreThresholdEd25519WorkerMaterial` consume credential-scoped authorization
through their material-store or material-restore request. There is no separate
public near-signer command that returns seal or unseal secret bytes.

Credential authorization handles are ephemeral. They may be surfaced in
in-memory SDK state as validation hints, but they are not durable restore
capabilities and must not be persisted as a substitute for a fresh passkey PRF
assertion or recovery-code entry. If a worker restarts, any previous handle is
invalid. Signing then returns `material_unseal_authorization_required` and the
caller may run the relevant step-up flow to install a fresh handle before
retrying.

The final setup path must seal the durable MPC artifact with a credential
authorization secret, not with the HSS output mask. `clientOutputMaskB64u` is
transitional naming for setup-boundary HSS output transport only. Final
worker/WASM commands use a byte-capable worker-local transport or a one-use
Rust-owned `clientOutputMaskHandle`, then zeroize the mask after opening the HSS
output. Use a `Uint8Array` only after proving the generated command path stays
inside structured-clone or direct worker-local transport and is never
JSON-serialized. Serialized generated requests should carry the one-use handle.
Any interim code that derives the sealed artifact key from
`clientOutputMaskB64u`, stores it as a string, or passes it through core material
logic is staging code and does not satisfy the completion criteria for no-HSS
restore.

Credential rotation requires an explicit reseal. A passkey credential change or
recovery-code rotation must install a fresh `seal` authorization handle, open
the existing sealed material with a valid old `unseal` handle or setup flow, and
write a replacement `Ed25519SealedWorkerMaterialV1` before the old credential is
discarded.

### Worker Command Spec

Add signer-core/WASM worker commands with this shape:

```ts
type Ed25519HssClientOutputMaskTransport =
  | {
      kind: 'worker_local_mask_bytes_v1';
      clientOutputMaskBytes: Uint8Array;
    }
  | {
      kind: 'rust_owned_mask_handle_v1';
      clientOutputMaskHandle: string;
    };

type Ed25519StoreWorkerMaterialFromHssOutputRequest = {
  kind: 'ed25519_store_worker_material_from_hss_output_v1';
  evaluatorDriverStateB64u: string;
  clientOutputMessageB64u: string;
  clientOutputMask: Ed25519HssClientOutputMaskTransport;
  expectedContextBindingB64u: string;
  bindingInput: Ed25519WorkerMaterialBindingInputWithoutVerifier;
  sealAuthorization: Ed25519WorkerMaterialSealAuthorization;
};

type Ed25519WorkerMaterialStored = {
  kind: 'ed25519_worker_material_stored_v1';
  materialHandle: string;
  materialBindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterialRef: string;
  sealedWorkerMaterialB64u: string;
  materialFormatVersion: 'ed25519_worker_material_v1';
  materialKeyId: string;
  signerSlot: number;
  keyVersion: string;
};

type Ed25519RestoreWorkerMaterialRequest = {
  kind: 'ed25519_restore_worker_material_v1';
  sealedMaterial: Ed25519SealedWorkerMaterialTransport;
  expectedMaterialBinding: Ed25519WorkerMaterialBindingV1;
  unsealAuthorization: Ed25519WorkerMaterialUnsealAuthorization;
};

type Ed25519ValidateWorkerMaterialRequest = {
  kind: 'ed25519_validate_worker_material_v1';
  materialHandle: string;
  expectedMaterialBinding: Ed25519WorkerMaterialBindingV1;
};

type Ed25519CreateClientPresignFromWorkerMaterialRequest = {
  kind: 'ed25519_create_client_presign_from_worker_material_v1';
  materialHandle: string;
  expectedMaterialBinding: Ed25519WorkerMaterialBindingV1;
  expectedSessionBinding: Ed25519WorkerMaterialSessionBindingV1;
};

type Ed25519SignClientPresignFromWorkerMaterialRequest = {
  kind: 'ed25519_sign_client_presign_from_worker_material_v1';
  materialHandle: string;
  expectedMaterialBinding: Ed25519WorkerMaterialBindingV1;
  expectedSessionBinding: Ed25519WorkerMaterialSessionBindingV1;
  signingPayloadB64u: string;
  serverCommitments: {
    hidingB64u: string;
    bindingB64u: string;
  };
};

type Ed25519WorkerMaterialErrorCode =
  | 'material_restore_required'
  | 'material_seal_authorization_required'
  | 'material_unseal_authorization_required'
  | 'material_restore_expired'
  | 'material_binding_mismatch'
  | 'material_scope_mismatch'
  | 'material_handle_not_loaded'
  | 'material_corrupt'
  | 'worker_unavailable';

type Ed25519WorkerMaterialFailure = {
  ok: false;
  code: Ed25519WorkerMaterialErrorCode;
  message: string;
};

type Ed25519StoreWorkerMaterialResult =
  | {
      ok: true;
      materialHandle: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      sealedWorkerMaterialRef: string;
      sealedWorkerMaterialB64u: string;
      materialFormatVersion: 'ed25519_worker_material_v1';
      materialKeyId: string;
      signerSlot: number;
      keyVersion: string;
    }
  | Ed25519WorkerMaterialFailure;

type Ed25519RestoreWorkerMaterialResult = Ed25519StoreWorkerMaterialResult;

type Ed25519ValidateWorkerMaterialResult =
  | {
      ok: true;
      materialHandle: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
    }
  | Ed25519WorkerMaterialFailure;

type Ed25519CreateClientPresignFromWorkerMaterialResult =
  | {
      ok: true;
      presignNonceHandle: string;
      clientCommitmentsMessageB64u: string;
    }
  | Ed25519WorkerMaterialFailure;

type Ed25519SignClientPresignFromWorkerMaterialResult =
  | {
      ok: true;
      clientSignatureShareMessageB64u: string;
    }
  | Ed25519WorkerMaterialFailure;
```

Rules:

- TypeScript passes opaque handles, sealed artifact references, binding digests,
  public verifier facts, and identity metadata only.
- The HSS client output mask is sensitive setup material. The final worker
  command receives it as a one-use Rust-owned handle by default. A transient
  `Uint8Array` is acceptable only for a verified byte-capable worker-local path
  that avoids JSON serialization. A generated or SDK wrapper that still exposes
  `clientOutputMaskB64u: string` is transitional staging code; decode it at the
  narrow request boundary, keep the string out of core material logic, and delete
  the string field from final command types.
- Core SDK and normal signing TypeScript never receive raw `xClientBaseB64u`,
  HSS evaluator material, PRF output bytes, recovery-code-derived seal bytes,
  or Ed25519 private material. Credential-confirm workers may handle transient
  browser credential bytes only long enough to install a worker-local
  authorization handle and zeroize the JS view.
- TypeScript may transport opaque FROST protocol messages returned by the
  worker. It must not derive, inspect, or mutate signing-share material.
- The worker validates the durable account, signing root, relayer key,
  participant set, material id, client verifier, and material binding digest
  before loading material.
- The worker validates the session binding, threshold session, signing grant,
  SigningWorker id, and expiry before producing presign commitments or signature
  share protocol messages.
- The worker returns `material_restore_required` for missing restore artifacts.
- The worker returns `material_seal_authorization_required` when a setup flow
  has HSS output but no active `seal` credential authorization handle.
- The worker returns `material_unseal_authorization_required` when the sealed
  artifact exists and no active credential-scoped unseal authorization handle is
  available.
- Expired or exhausted credential handles map to
  `material_unseal_authorization_required` for restore and
  `material_seal_authorization_required` for setup. Expired session activation
  fails before presign/sign-presign as `material_scope_mismatch`.
  `material_restore_expired` is reserved for a future sealed-artifact TTL and
  must not be used for normal Wallet Session expiry.
- `material_binding_mismatch` and `material_scope_mismatch` are fail-closed and
  never attempt fallback reconstruction.

SDK error mapping:

```ts
type Ed25519SigningMaterialReadinessFailure =
  | {
      kind: 'material_restore_required';
      nearAccountId: string;
      signerSlot: number;
      materialKeyId?: string;
      signingRootId: string;
      signingRootVersion: string;
      relayerKeyId: string;
      keyVersion: string;
      repairKind: 'ed25519_worker_material_setup';
      message: string;
    }
  | {
      kind: 'material_seal_authorization_required';
      nearAccountId: string;
      signerSlot: number;
      materialKeyId: string;
      credentialSource: 'passkey_prf' | 'recovery_code';
      message: string;
    }
  | {
      kind: 'material_unseal_authorization_required';
      nearAccountId: string;
      signerSlot: number;
      materialKeyId: string;
      credentialSource: 'passkey_prf' | 'recovery_code';
      message: string;
    }
  | {
      kind: 'material_integrity_failure';
      code: 'material_binding_mismatch' | 'material_scope_mismatch' | 'material_corrupt';
      nearAccountId: string;
      signerSlot: number;
      materialKeyId: string;
      message: string;
    }
  | {
      kind: 'worker_unavailable';
      retryable: true;
      message: string;
    };
```

`material_handle_not_loaded` is not exposed directly. The SDK first attempts
restore when a sealed ref exists. It returns `material_restore_required` when no
sealed ref exists.

### Rust And WASM Implementation Points

Add a signer-core command module:

```text
crates/signer-core/src/commands/ed25519_worker_material.rs
```

That module owns:

- `Ed25519WorkerMaterialBindingV1`
- `Ed25519WorkerMaterialSessionBindingV1`
- canonical binding digest construction
- canonical session binding digest construction
- sealed artifact encode/decode
- material plaintext encode/decode
- HKDF-SHA256 seal-key derivation
- ChaCha20Poly1305 seal/open with explicit AAD
- verifying-share derivation from plaintext material
- store/restore/validate result types exported through `ts-rs`
- create-presign and sign-presign result types exported through `ts-rs`

Update:

- `crates/signer-core/src/commands/mod.rs`
- `crates/signer-core/tests/export_typescript_schemas.rs`
- `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`

Add WASM worker request variants at the end of the existing enums:

```text
wasm/near_signer/src/types/worker_messages.rs
wasm/near_signer/src/lib.rs
```

Required new variants:

- `StoreThresholdEd25519WorkerMaterialFromHssOutput`
- `RestoreThresholdEd25519WorkerMaterial`
- `ValidateThresholdEd25519WorkerMaterial`
- `CreateThresholdEd25519ClientPresignFromWorkerMaterial`
- `SignThresholdEd25519ClientPresignFromWorkerMaterial`
- `BurnThresholdEd25519WorkerMaterial`
- `PutThresholdEd25519SealedWorkerMaterial`
- `ReadThresholdEd25519SealedWorkerMaterial`
- `DeleteThresholdEd25519SealedWorkerMaterial`

The request and response variants must be appended to preserve existing numeric
enum values during this development branch. Store, restore, validate,
create-presign, and sign-presign each need explicit success and failure response
payloads. The TypeScript worker types in
`packages/sdk-web/src/core/types/signer-worker.ts` must be regenerated or updated
to mirror those variants.

Current `WorkerRequestType` ends at
`CreateThresholdEd25519RoleSeparatedNormalSigningClientShare = 19`. Append in
this order:

```text
20 StoreThresholdEd25519WorkerMaterialFromHssOutput
21 RestoreThresholdEd25519WorkerMaterial
22 ValidateThresholdEd25519WorkerMaterial
23 CreateThresholdEd25519ClientPresignFromWorkerMaterial
24 SignThresholdEd25519ClientPresignFromWorkerMaterial
25 BurnThresholdEd25519WorkerMaterial
26 PutThresholdEd25519SealedWorkerMaterial
27 ReadThresholdEd25519SealedWorkerMaterial
28 DeleteThresholdEd25519SealedWorkerMaterial
```

Current `WorkerResponseType` ends at
`CreateThresholdEd25519RoleSeparatedNormalSigningClientShareFailure = 43`.
Append success/failure pairs in the same request order:

```text
44 StoreThresholdEd25519WorkerMaterialFromHssOutputSuccess
45 StoreThresholdEd25519WorkerMaterialFromHssOutputFailure
46 RestoreThresholdEd25519WorkerMaterialSuccess
47 RestoreThresholdEd25519WorkerMaterialFailure
48 ValidateThresholdEd25519WorkerMaterialSuccess
49 ValidateThresholdEd25519WorkerMaterialFailure
50 CreateThresholdEd25519ClientPresignFromWorkerMaterialSuccess
51 CreateThresholdEd25519ClientPresignFromWorkerMaterialFailure
52 SignThresholdEd25519ClientPresignFromWorkerMaterialSuccess
53 SignThresholdEd25519ClientPresignFromWorkerMaterialFailure
54 BurnThresholdEd25519WorkerMaterialSuccess
55 BurnThresholdEd25519WorkerMaterialFailure
56 PutThresholdEd25519SealedWorkerMaterialSuccess
57 PutThresholdEd25519SealedWorkerMaterialFailure
58 ReadThresholdEd25519SealedWorkerMaterialSuccess
59 ReadThresholdEd25519SealedWorkerMaterialFailure
60 DeleteThresholdEd25519SealedWorkerMaterialSuccess
61 DeleteThresholdEd25519SealedWorkerMaterialFailure
```

Replace the TypeScript raw-material registry in
`packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
with a Rust-owned registry. The TypeScript worker may keep request ids,
operation queues, and nonce handles. It must not keep `xClientBaseB64u`.

The Rust registry can live in the WASM wrapper crate:

```text
wasm/near_signer/src/threshold/worker_material.rs
```

It stores:

- `materialHandle`
- plaintext Ed25519 client MPC share bytes
- `clientVerifyingShareB64u`
- `materialBindingDigest`
- material format version
- loaded-at timestamp
- in-flight presign activation expiry keyed by nonce handle

The registry exposes only store, restore, validate, create-presign, sign-presign,
and burn operations through worker messages.

`materialHandle` values are random worker-local capabilities. Persisted handles
are hints only. A worker restart invalidates loaded handles and requires restore
from `sealedWorkerMaterialRef`. The worker must expose a burn operation for
logout, account switch, and explicit material reset.

The sealed storage resolver must also live behind worker-owned commands:

- `PutThresholdEd25519SealedWorkerMaterial`
- `ReadThresholdEd25519SealedWorkerMaterial`
- `DeleteThresholdEd25519SealedWorkerMaterial`

Storage refs must include a namespace and digest, for example
`ed25519-worker-material-v1:<materialBindingDigest>`. Missing, corrupt, or
binding-mismatched refs return typed material errors. The first version assumes
worker-local serialization and fails closed when concurrent writers race.

Storage command shapes:

```ts
type PutThresholdEd25519SealedWorkerMaterialRequest = {
  kind: 'put_threshold_ed25519_sealed_worker_material_v1';
  sealedMaterial: Ed25519SealedWorkerMaterialV1;
};

type PutThresholdEd25519SealedWorkerMaterialResult =
  | {
      ok: true;
      sealedWorkerMaterialRef: string;
      materialBindingDigest: string;
    }
  | Ed25519WorkerMaterialFailure;

type ReadThresholdEd25519SealedWorkerMaterialRequest = {
  kind: 'read_threshold_ed25519_sealed_worker_material_v1';
  sealedWorkerMaterialRef: string;
  expectedMaterialBindingDigest: string;
};

type ReadThresholdEd25519SealedWorkerMaterialResult =
  | {
      ok: true;
      sealedMaterial: Ed25519SealedWorkerMaterialV1;
    }
  | Ed25519WorkerMaterialFailure;

type DeleteThresholdEd25519SealedWorkerMaterialRequest = {
  kind: 'delete_threshold_ed25519_sealed_worker_material_v1';
  sealedWorkerMaterialRef: string;
  expectedMaterialBindingDigest: string;
};

type DeleteThresholdEd25519SealedWorkerMaterialResult =
  | { ok: true; deleted: true }
  | Ed25519WorkerMaterialFailure;
```

### SDK Web Implementation Points

Update SDK web in these places:

- `packages/sdk-web/src/core/types/signer-worker.ts`: add worker request/result
  types for the new Ed25519 worker material commands and remove raw
  `xClientBaseB64u` from normal signing material requests after the Rust-owned
  registry lands.
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`:
  keep HSS client wrappers limited to HSS client request, evaluator artifact,
  output opening, and seed export. Worker-material store, restore, validate,
  create-presign, and sign-presign wrappers live in the near-signer worker
  wrapper layer.
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
  and the recovery-confirm worker path: replace raw PRF/recovery-code secret
  return paths with credential-scoped unseal authorization handle creation and
  consume commands.
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`:
  delete the interim `deriveThresholdEd25519ClientVerifyingShareFromPrfFirst()`
  setup bridge after `Ed25519PrepareWorkerMaterialSealAuthorization` lands.
  Setup should ask the issuer for `{ materialKeyId, sealAuthorization }`, pass
  verifier-free public key identity facts to store, and persist the
  `materialBindingDigest` returned after store opens the HSS output.
- `packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts` and
  `packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`:
  add wrappers for the final `prepare seal authorization` and `prepare unseal
authorization` commands. The lower-level install commands may remain inside
  the worker/WASM implementation, but app/session code must call the prepared
  issuer commands.
- `packages/sdk-web/src/core/signingEngine/session/passkey/prfCache.ts` and
  `prfClaim.ts`: stop returning raw `prfFirstB64u`; return
  a short-lived `passkey_prf_material_authorization_handle_v1` for the current
  worker only.
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`:
  replace the passkey reconstruction path that passes `prfFirstB64u` through
  core TypeScript with a credential-boundary seal/unseal authorization issuer.
  Persist only public material facts and handles.
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`:
  rename the Ed25519 recovery material boundary from `prfFirstB64u` to
  `recoveryCodeSecret32`, derive it inside the email/recovery worker boundary,
  and issue recovery-code material authorization handles without exposing a
  base64url secret string to core session code.
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssClientBase.ts`:
  replace the HSS-named loaded-handle helper with
  `requireThresholdEd25519WorkerMaterial()`.
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`:
  add `sealedWorkerMaterialRef`, `materialFormatVersion`,
  `materialBindingDigest`, `materialKeyId`, `signerSlot`, and `keyVersion` to
  the Ed25519 material record boundary; delete `xClientBaseB64u` after
  stale-record pruning is in place.
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`:
  persist the sealed material reference and public durable material facts
  separately from warm activation facts.
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`:
  classify Ed25519 records as `signable`, `restore_available`, or
  `restore_unavailable`; reject raw client-base records at the boundary.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519SigningMaterialReadiness.ts`:
  become the single lazy materialization helper for NEAR transactions, NEP-413,
  and delegate signing.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`,
  `signNep413.ts`, and `signDelegate.ts`: call the shared restore helper before
  Router A/B normal signing inputs are built.

### Worker Material Storage And Binding

Persist the sealed worker-owned material reference with durable material facts:

- `nearAccountId`
- `signerSlot`
- `signingRootId`
- `signingRootVersion`
- `relayerKeyId`
- `keyVersion`
- `participantIds`
- `clientVerifyingShareB64u`
- `materialBindingDigest`
- `materialKeyId`
- `materialFormatVersion`
- `createdAtMs`

Persist warm-session activation facts separately:

- `thresholdSessionId`
- `signingGrantId`
- `runtimePolicyScope`
- `signingWorkerId`
- `expiresAtMs`
- server-authoritative budget fields owned by Refactor 70

The persisted SDK material record stores:

- `sealedWorkerMaterialRef`
- `materialFormatVersion`
- `materialHandle` only in the loaded-handle branch, as a validation hint
- `materialBindingDigest`
- `clientVerifyingShareB64u`
- the durable material fields listed above

`sealedWorkerMaterialRef` may point to IndexedDB, secure-confirm worker storage,
or another SDK persistence boundary. The referenced value is an
`Ed25519SealedWorkerMaterialV1` blob. New writes must never include raw client
base material.

The warm-session record stores activation facts and derives
`Ed25519WorkerMaterialSessionBindingV1` when signing begins. A material record
can outlive many warm sessions. A warm session can use material only when its
activation binding links to the durable `materialBindingDigest`.

### Existing Account Behavior

Existing accounts may have Wallet Session records without sealed worker-owned
Ed25519 material.

Required behavior:

- Unlock still succeeds when Wallet Session auth and budget are valid.
- Signing with a missing sealed worker material artifact returns
  `material_restore_required` before Router A/B final signing.
- `material_restore_required` includes `nearAccountId`, `signerSlot`,
  `materialKeyId` when known, `signingRootId`, `signingRootVersion`,
  `relayerKeyId`, `keyVersion`, `repairKind`, and a user-action safe message.
- The SDK may offer an explicit repair/setup flow that runs HSS or another
  key-material setup ceremony after user approval.
- Daily signing must not trigger that repair implicitly.
- A one-time repair flow must write the same worker-owned sealed artifact used
  by registration, add-signer, and device-sync setup.

This keeps the normal path no-HSS while preserving an explicit recovery route
for old accounts.

The public repair entrypoint should be a narrow command such as
`repairThresholdEd25519WorkerMaterial()`. It must require fresh user
authorization, run setup material derivation inside signer-core/WASM, persist a
new sealed artifact, and return the same material metadata as registration.

## Target Model

Split the lifecycle into authorization and material state:

```ts
type Ed25519SigningMaterialRestorePointer =
  | {
      kind: 'restore_available_with_handle';
      sealedWorkerMaterialRef: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      materialKeyId: string;
      keyVersion: string;
      materialFormatVersion: 'ed25519_worker_material_v1';
      materialHandleHint: string;
      xClientBaseB64u?: never;
    }
  | {
      kind: 'restore_available_sealed_only';
      sealedWorkerMaterialRef: string;
      materialBindingDigest: string;
      clientVerifyingShareB64u: string;
      materialKeyId: string;
      keyVersion: string;
      materialFormatVersion: 'ed25519_worker_material_v1';
      materialHandleHint?: never;
      xClientBaseB64u?: never;
    }
  | {
      kind: 'restore_missing';
      reason: 'missing_sealed_artifact';
      sealedWorkerMaterialRef?: never;
      materialBindingDigest?: never;
      clientVerifyingShareB64u?: never;
      materialKeyId?: never;
      keyVersion?: never;
      xClientBaseB64u?: never;
    };

type WarmEd25519SigningSessionAuthorization = {
  kind: 'warm_ed25519_signing_session_authorized';
  curve: 'ed25519';
  nearAccountId: string;
  signerSlot: number;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: readonly number[];
  thresholdSessionKind: 'jwt';
  thresholdSessionId: string;
  signingGrantId: string;
  walletSessionJwt: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
  remainingUses: number;
  expiresAtMs: number;
  unsealAuthorization: WarmUnsealAuthorizationState;
  materialState: 'material_pending';
  materialRestore: Ed25519SigningMaterialRestorePointer;
  ed25519WorkerMaterialHandle?: never;
  ed25519WorkerMaterialBindingDigest?: never;
  clientVerifyingShareB64u?: never;
};

type WarmUnsealAuthorizationState =
  | {
      kind: 'hot_passkey_prf_unseal_authorization';
      handle: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | {
      kind: 'hot_recovery_code_unseal_authorization';
      handle: string;
      remainingUses: number;
      expiresAtMs: number;
    }
  | {
      kind: 'unseal_authorization_required';
      credentialSource: 'passkey_prf' | 'recovery_code';
      reason: 'not_collected' | 'worker_restart' | 'expired' | 'exhausted';
      handle?: never;
      remainingUses?: never;
      expiresAtMs?: never;
    };
```

Ed25519 signing readiness remains stricter:

```ts
type Ed25519SigningMaterialReady = {
  kind: 'ed25519_signing_material_ready';
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  signerSlot: number;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: readonly number[];
  signingWorkerId: string;
  materialHandle: string;
  materialBindingDigest: string;
  sessionBindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterialRef: string;
  materialKeyId: string;
  materialFormatVersion: 'ed25519_worker_material_v1';
  materialBinding: Ed25519WorkerMaterialBindingV1;
  sessionBinding: Ed25519WorkerMaterialSessionBindingV1;
  xClientBaseB64u?: never;
};
```

Unlock returns after `warm_ed25519_signing_session_authorized`. Signing requires
`ed25519_signing_material_ready`, materializing it lazily when needed.

## No-HSS Unlock Spec

Unlock should do exactly this for Ed25519:

1. Build the Wallet Session policy with `buildEd25519SessionPolicy()`.
2. Collect or reuse the authorization proof for that policy.
3. Mint the Wallet Session through `mintEd25519WalletSession()`.
4. Persist the warm capability with `persistWarmSessionEd25519Capability()`.
5. If the unlock credential flow already produced passkey PRF or recovery-code
   material, install a short-lived worker-owned `unseal` authorization handle
   and keep only the opaque handle metadata in current SDK state.
6. If no live handle is available, record `unseal_authorization_required`.
   Unlock still succeeds when Wallet Session auth and budget are valid.
7. Assert the authorization record and any live unseal authorization metadata
   are active.
8. Return unlock success.

Unlock should skip:

- `prewarmThresholdEd25519ClientBaseFromCredential()`
- `reconstructThresholdEd25519SigningMaterialFromWarmSession()`
- `runThresholdEd25519HssCeremonyWithMaterialHandle()`
- signing-lane postconditions that require `ed25519WorkerMaterialHandle`

The unlock postcondition should read the persisted Ed25519 record and warm
unseal authorization metadata. It should validate:

- record exists for the selected account and signer slot
- `signerSlot` is a safe positive integer
- auth method matches the unlock route
- `thresholdSessionKind === 'jwt'`
- `thresholdSessionId` is non-empty
- `signingGrantId` is non-empty
- `walletSessionJwt` is non-empty
- `relayerKeyId` and `keyVersion` are non-empty
- `runtimePolicyScope` exists
- signing root id and version resolve from `runtimePolicyScope`
- `routerAbNormalSigning.signingWorkerId` is non-empty
- `remainingUses > 0`
- `expiresAtMs > now`
- when `unsealAuthorization.kind` is hot, the handle metadata is non-empty,
  unexpired, and has positive remaining uses
- when `unsealAuthorization.kind === 'unseal_authorization_required'`, the
  reason and credential source are explicit

It should not inspect `ed25519WorkerMaterialHandle`,
`ed25519WorkerMaterialBindingDigest`, `clientVerifyingShareB64u`, or
`xClientBaseB64u`.

## No-HSS Transaction Signing Spec

The first transaction after unlock should use this shape:

1. `resolveNearSigningSessionAuthContext()` reads the warm Ed25519 capability.
2. `deriveEd25519CapabilityState()` returns `material_pending` when auth and
   budget are present and loaded worker material is unavailable.
3. `resolvePlannerReadinessForEd25519()` treats passkey `material_pending` as
   ready only when remaining uses cover the transaction signature count.
4. The confirmation flow chooses `warm_session`.
5. `signTransactions()` classifies the stored record with
   `classifyRouterAbEd25519PersistedSigningRecord()`.
6. For a loaded handle, the worker validates the handle against
   `Ed25519WorkerMaterialBindingV1`.
7. If validation fails and `sealedWorkerMaterialRef` exists, signing calls
   `RestoreThresholdEd25519WorkerMaterial` with the expected durable material
   binding and an active credential-scoped unseal authorization handle.
8. For `restore_available`, signing calls the same restore command directly.
9. The worker opens the sealed client MPC share internally, loads it into the
   Rust registry, validates the material binding digest and client verifier, and
   returns material handle metadata.
10. If the sealed artifact is missing, signing returns
    `material_restore_required` before Router A/B final signing.
11. If the artifact exists and unseal authorization is unavailable, signing
    returns `material_unseal_authorization_required` before Router A/B final
    signing. The shared restore helper does not run UI prompts itself; the
    caller may run passkey PRF or recovery-code step-up to install a fresh
    `unseal` handle and retry.
12. The record is updated through
    `persistStoredThresholdEd25519SessionMaterialHandle()` and the sealed-record
    refresh path keeps `sealedWorkerMaterialRef`.
13. `resolveRouterAbEd25519WalletSessionStateFromRecord()` must now parse a
    signable record.
14. `requireRouterAbEd25519NormalSigningReadyState()` builds
    `Ed25519WorkerMaterialSessionBindingV1` and validates all Router A/B signing
    prerequisites.
15. The worker validates the session binding before create-presign and
    sign-presign.
16. Router A/B normal signing prepare/finalize can run.

The above chain guarantees that transaction signing has material before
producing a signature and never invokes HSS during a normal signing operation.
Raw client-base cache reuse in TypeScript is out of scope for the target design.

NEP-413 and NEP-461 delegate signing must call the same restore helper before
they build Router A/B normal-signing inputs. They must not maintain a separate
material path.

## Resolved Spec Gaps

These decisions close the remaining ambiguities before implementation continues:

1. Credential authorization handles are ephemeral worker capabilities. They are
   never durable restore artifacts. Persisted SDK records may keep only public
   material metadata and, at most, an opaque current-worker handle hint that
   must validate through the worker before use.
2. Setup sealing and material restore are different purposes. Registration,
   add-signer, device-sync, and explicit repair use a `seal` authorization
   handle to create or replace `Ed25519SealedWorkerMaterialV1`. Normal signing
   uses an `unseal` authorization handle to restore that artifact.
3. `clientOutputMaskB64u` is transitional setup-boundary transport naming. HSS
   output-mask data may be used to open setup material only as Rust-owned bytes
   or a transient `Uint8Array`, then it must be zeroized. The durable artifact
   must be sealed to passkey PRF or recovery-code-derived material.
4. Unlock does not require a live unseal handle. A missing, expired, exhausted,
   or worker-lost handle becomes `unseal_authorization_required` in the warm
   authorization state. First sign returns
   `material_unseal_authorization_required` before Router A/B signing and may
   prompt for passkey PRF or recovery-code authorization.
5. Email OTP is account-control authorization for email accounts. It is not a
   durable MPC-material sealing secret. Error sources and state names must use
   `recovery_code` for the email-account material secret path.
6. There are no sealed PRF-claim or sealed unseal-authorization restore refs in
   this refactor. Reintroducing one would be a separate design because it would
   create another secret persistence surface.
7. Credential rotation is an explicit reseal flow. The system must write a new
   sealed material artifact under the new credential before the old credential
   path is removed.

## Auditor Checklist Resolution

- [x] Secret byte request shapes are allowed only at credential-confirm worker
      boundaries. Core SDK, persistence, route clients, warm-session state, and
      signing flows may not construct requests carrying `prfFirstBytes` or
      `recoveryCodeSecret32`.
- [x] `clientOutputMaskB64u` is transitional naming. Final worker commands use
      byte-capable worker-local transport or a one-use Rust-owned handle, and
      any remaining string field is a boundary-decoding task scheduled for
      deletion.
- [x] Handle lifetime and use-count defaults are explicit: v1 `seal` and
      `unseal` handles are one-use, default to a 60-second TTL, and are capped
      at 5 minutes unless a future typed server-authorized capability branch
      permits more.
- [x] Server policy authority remains explicit. The worker handle is a local
      material capability and cannot replace Wallet Session, Signing Grant,
      budget, route, or step-up authorization enforced by the server.
- [x] `materialKeyId` is stable key identity. `materialBindingDigest` is sealed
      artifact identity and may change across reseal or credential rotation
      while preserving the same `materialKeyId`.
- [x] Error naming remains domain-separated. Warm-session authorization state
      uses `unseal_authorization_required`; worker material operations return
      `material_unseal_authorization_required`.

## Registration Output Spec

Registration is allowed to run HSS because it is a key-material setup flow. Its
completion must leave the client with durable signer-core-owned material for
normal signing:

1. Registration runs the Ed25519 HSS derivation ceremony.
2. signer-core/WASM opens the HSS client output internally.
3. signer-core/WASM stores the resulting client MPC share in worker memory.
4. signer-core/WASM consumes a live `seal` credential authorization handle for
   the selected passkey PRF or recovery-code path.
5. signer-core/WASM seals the same material to an
   `Ed25519SealedWorkerMaterialV1` artifact using that credential-derived
   secret.
6. signer-core/WASM emits:
   - opaque material handle
   - durable material binding digest
   - client verifying share
   - sealed worker material artifact or restore reference
7. TypeScript persists only the opaque restore artifact/reference, handle
   metadata, public verifier facts, durable material identity, Wallet Session
   metadata, and lane scope.
8. TypeScript never receives raw `xClientBaseB64u` or private signing material.
9. Daily unlock restores authorization only.
10. Daily signing validates or restores the worker material handle without HSS.

Registration, add-signer, device-sync, and explicit repair must all derive the
same durable material binding shape. They must choose and persist
`materialKeyId` before sealing so later warm sessions can link activation to the
right durable artifact.

## Invariants

- Wallet unlock never runs Ed25519 HSS material reconstruction by default.
- Wallet unlock may return an Ed25519 warm session in `material_pending`.
- A `material_pending` Ed25519 warm session is usable for auth planning and
  budget admission.
- A signing operation cannot produce an Ed25519 signature until material
  handle validation succeeds.
- Reusing an already loaded worker material handle still skips HSS.
- Reusing a valid signer-core-owned sealed material restore artifact skips
  relay HSS after the worker restore path exists.
- Durable sealed material is never bound to `thresholdSessionId`,
  `signingGrantId`, session expiry, or server budget.
- Session activation is never treated as proof that durable material exists.
- Signing requires both a valid durable material binding and a valid session
  activation binding.
- Normal transaction signing must not call
  `ensureThresholdEd25519HssSigningMaterial()`,
  `runThresholdEd25519HssCeremonyWithMaterialHandle()`, or any HSS route.
- TypeScript must not persist, deserialize, validate, or pass raw
  `xClientBaseB64u` as a signing material cache.
- TypeScript must not keep raw Ed25519 signing material in a worker-local map.
- Registration and key export keep their existing HSS requirements.
- Compatibility handling stays at persistence and request boundaries only.

## Non-Goals

- Redesign the Ed25519 HSS protocol.
- Persist raw Ed25519 client signing material outside the worker boundary.
- Treat diagnostics or log state as control flow.
- Add legacy flags for old unlock behavior.
- Keep a permanent eager-HSS unlock path.

## Phase 1: Rename The Unlock Contract

- [x] Introduce an internal `WarmEd25519SigningSessionAuthorization` domain
      type.
- [x] Make the type carry required identity, budget, auth, lane, and scope
      fields.
- [x] Keep Ed25519 material handle fields out of the authorization type.
- [x] Add type fixtures rejecting authorization objects that include material
      fields.
- [x] Add type fixtures rejecting signing-material-ready objects without a
      material handle, material binding digest, and client verifying share.

## Phase 1A: Finalize Worker-Material Protocol Spec

- [x] Split durable `Ed25519WorkerMaterialBindingV1` from per-session
      `Ed25519WorkerMaterialSessionBindingV1` in generated command types.
- [x] Define `materialKeyId` as the digest of account signer slot, signing
      root, relayer key, key version, and material format.
- [x] Define canonical JSON rules for material binding digests, session binding
      digests, and sealed-artifact AAD.
- [x] Add Rust/TypeScript digest vectors covering field order, integer
      encoding, array order, base64url encoding, and runtime policy
      representation.
- [x] Lock the sealing primitive to ChaCha20Poly1305 with HKDF-SHA256,
      12-byte random nonce, explicit AAD, and signer-core-owned plaintext
      encoding.
- [x] Define credential-scoped unseal authorization handles: owner, scope,
      max-use, consume, expiry, and error semantics for passkey PRF and
      recovery-code paths.
- [x] Split credential authorization purpose into `seal` and `unseal`; setup
      flows may create sealed artifacts only with a `seal` handle, while normal
      signing restore may open artifacts only with an `unseal` handle.
- [x] Decide that credential authorization handles are ephemeral worker
      capabilities, not durable restore artifacts.
- [x] Decide that `clientOutputMaskB64u` must not be the production sealing
      secret for durable worker material.
- [x] Define the worker-local command used by near-signer to consume
      credential authorization handles without returning PRF.first,
      recovery-code-derived seal bytes, or derived seal/unseal keys to
      TypeScript.
- [x] Define the sealed material storage resolver API, storage-ref namespace,
      ref encoding, delete behavior, corrupt-blob behavior, and first-version
      cross-tab rule.
- [x] Define `materialHandle` lifecycle: random generation, restart
      invalidation, validation, burn, and persistence as a hint only.
- [x] Define exact worker request/response enum names, append order, success
      payloads, failure payloads, and SDK error mapping for store, restore,
      validate, create-presign, and sign-presign.
- [x] Define the public explicit-repair entrypoint and structured
      `material_restore_required` payload for existing accounts without sealed
      worker material.
- [x] Define background restore budget and authorization semantics before
      exposing a background restore option.

Immediate implementation order:

1. Reuse the existing signer-core and near-signer worker-material protocol.
   Do not duplicate store, restore, validate, sealed-artifact storage,
   credential-authorization install, presign, or sign-presign code.
2. Add the missing prepared issuer wrapper only where it removes transitional
   TypeScript binding reconstruction and raw PRF/recovery-material routing.
3. Tighten existing near-signer material authorization policy: one-use v1
   handles, TTL defaults/caps, secret-boundary guards, and `clientOutputMaskB64u`
   cleanup.
4. Replace registration/add-signer/device-sync HSS output opening with
   `StoreThresholdEd25519WorkerMaterialFromHssOutput`.
5. Update SDK persistence boundaries to reject raw client material and persist
   durable material records with `signerSlot`, `keyVersion`, `materialKeyId`,
   and `materialBindingDigest`.
6. Replace the current fail-closed signing helper with worker restore, then
   route NEAR transaction, NEP-413, and delegate signing through the same helper.

## Phase 1B: Persist Worker-Owned Client MPC Share At Setup

- [x] Add `crates/signer-core/src/commands/ed25519_worker_material.rs` with
      material binding digest, sealed artifact, plaintext encoding, and result
      types.
- [x] Implement `Ed25519WorkerMaterialKeyIdentityV1` and `materialKeyId`
      construction in signer-core.
- [x] Implement `Ed25519WorkerMaterialSessionBindingV1` and session binding
      digest construction in signer-core.
- [x] Implement ChaCha20Poly1305/HKDF-SHA256 sealing with AAD and native
      negative vectors.
- [x] Add an AAD-capable signer-core ChaCha20Poly1305 helper for worker material
      sealing. Do not reuse the current no-AAD string helper for sealed client
      MPC shares.
- [x] Export the Ed25519 worker-material command types from
      `crates/signer-core/src/commands/mod.rs`.
- [x] Update `crates/signer-core/tests/export_typescript_schemas.rs` and
      regenerate `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`.
- [x] Add `wasm/near_signer/src/threshold/worker_material.rs` with a Rust-owned
      in-memory registry keyed by `materialHandle`.
- [x] Append near-signer `WorkerRequestType` and `WorkerResponseType` variants
      for store, restore, validate, create-presign-from-handle, and
      sign-presign-from-handle.
- [x] Wire `StoreThresholdEd25519WorkerMaterialFromHssOutput` into the browser
      near-signer WASM worker so HSS client output opens and stores the loaded
      material handle inside the Rust-owned registry.
- [x] Add worker-owned sealed-material put/read/delete commands and route
      `sealedWorkerMaterialRef` resolution through the worker boundary.
- [x] Map restore and sealed-material storage failures through the SDK worker
      boundary as `Ed25519WorkerMaterialFailure` result unions instead of
      generic worker runtime errors.
- [x] Store generated Ed25519 worker-material bindings in the near-signer Rust
      registry and require exact material/session binding validation before
      material-backed presign creation or sign-presign.
- [x] Route NEAR transaction, NEP-413, delegate, and presign-pool material use
      through SDK wrappers that pass full `expectedMaterialBinding` and
      `expectedSessionBinding` to the near-signer worker.
- [x] Add credential-scoped unseal authorization consume commands for passkey
      PRF and recovery-code paths. Secret bytes and derived unseal keys must
      stay inside worker/WASM code.
- [x] Add internal install commands for passkey PRF and recovery-code material
      authorization handles. The commands may accept transient `Uint8Array`
      secret bytes only at the credential-confirm worker boundary.
- [x] Rename generated signer-core/near-signer `SealKeySource` types to
      credential authorization types with explicit `purpose: 'seal' | 'unseal'`.
- [x] Replace the interim HSS-output-mask sealing path with credential-derived
      sealing through a live `seal` authorization handle.
- [x] Rename email-account Ed25519 material values that are currently surfaced
      as `prfFirstB64u` to recovery-code material handles or
      `recoveryCodeSecret32` boundary inputs.
- [x] Add source guards proving `clientOutputMaskB64u` is used only to open HSS
      setup output and is never passed as the durable artifact sealing secret.
- [x] Replace `OpenThresholdEd25519HssClientOutput` use in registration setup
      with `StoreThresholdEd25519WorkerMaterialFromHssOutput`, so TypeScript
      never receives `xClientBaseB64u`.
- [x] Update registration finalization to persist `sealedWorkerMaterialRef`,
      `materialFormatVersion`, `materialBindingDigest`, `materialKeyId`,
      `signerSlot`, `keyVersion`, `clientVerifyingShareB64u`, and the loaded
      `materialHandle` hint when the worker returns one.
- [x] Update add-signer and device-sync setup flows to produce the same sealed
      restore artifact/reference.
- [x] Replace raw PRF.first signing-session caches with worker-owned,
      short-lived passkey PRF credential authorization handles for the current
      worker only. - `passkey-confirm.worker.ts` now stores warm-session policy by
      worker-local PRF handle and keeps raw PRF material only behind the
      worker-owned handle store/boundary. - Source guard:
      `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` proves the
      warm-session cache stores `prfFirstHandle`, not `prfFirstB64u`.
- [x] Remove sealed PRF/unseal-authorization restore refs from the target model
      and tests for this refactor.
- [x] Delete TypeScript persistence fields that carry raw `xClientBaseB64u`
      after boundary parsers can reject or prune old records.
- [x] Add type fixtures rejecting any registration persistence object that
      includes raw client signing material.
- [x] Add type fixtures rejecting material records without `signerSlot`,
      `keyVersion`, `materialKeyId`, and `materialBindingDigest`.
- [x] Add native Rust tests proving sealed artifact binding mismatch, verifier
      mismatch, account mismatch, material id mismatch, and corrupt ciphertext
      fail closed.
- [x] Add Rust/WASM tests proving session grant mismatch, worker mismatch,
      session-binding digest mismatch, and expiry fail closed before presign or
      sign-presign.

Implementation note:

- The near-signer Rust worker now constructs generated material bindings when
  storing HSS output, stores those bindings with loaded material handles, and
  validates material plus session bindings before using a handle for presign or
  sign-presign.
- The HSS output store now seals the opened worker material inside near-signer
  WASM, returns `sealedWorkerMaterialRef` plus inline sealed artifact bytes, and
  SDK web persists those durable restore facts with the loaded material handle
  hint.
- Credential-scoped material authorization now exists for passkey PRF and
  recovery-code material. Store consumes a one-use `seal` handle scoped to the
  stable `materialKeyId`; restore consumes a fresh `unseal` handle scoped to the
  durable `materialBindingDigest`.
- The HSS material-handle setup path prepares a `materialKeyId`-scoped seal
  authorization in the near-signer worker before store. Store opens HSS output
  inside WASM, derives the public client verifier, builds the public material
  binding digest, verifies the prepared key id, and seals the worker material.
  `clientOutputMaskB64u` remains only the HSS output opener.
- Passkey warm-session reconstruction now installs passkey PRF seal handles.
  Email-OTP reconstruction now uses the recovery-code material authorization
  variant at the material boundary, though remaining legacy variable names
  still surface the value as `prfFirstB64u` until Phase 1C lands.
- Email-account Ed25519 restore still needs explicit signer-slot and
  key-material timestamp persistence. The current implementation uses the
  existing single-signer email recovery convention at the reconstruction
  boundary; replace that with persisted activation metadata before treating
  email-account no-HSS restore as complete.

Code reuse audit, June 20, 2026:

- Existing signer-core command types already cover durable material binding,
  session binding, sealed artifact format, credential authorization handles,
  store, restore, validate, create-presign, sign-presign, and sealed-material
  put/read/delete in
  `crates/signer-core/src/commands/ed25519_worker_material.rs`.
- Existing near-signer WASM exports already implement store-from-HSS,
  passkey/recovery-code material authorization install, restore, validate,
  sealed-material put/read/delete, create-presign, sign-presign, and presign
  burn in `wasm/near_signer/src/threshold/worker_material.rs`.
- Existing SDK web near-signer worker custom request handling already calls
  those direct WASM exports from
  `packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`.
- The unified Rust `handle_signer_message` path still has stale "not wired"
  branches for worker-material message enum variants. Treat that as wiring
  cleanup only; do not reimplement the direct worker-material exports.
- Phase 1C must add only the missing prepared issuer boundary, local capability
  tightening, source guards, tests, and call-chain cleanup. It must not create a
  second worker-material registry or duplicate seal/restore/presign logic.

## Remaining Implementation Specs

These specs make the remaining tasks implementation-grade. Keep the work in this
order so cleanup does not churn files that still need semantic changes.

### 1. Passkey PRF Boundary Cleanup

Current state:

- `packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts` owns the
  passkey material authorization helpers.
- `prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential()`
  extracts PRF.first from the credential internally, decodes it to `Uint8Array`,
  passes bytes to the near-signer issuer, and zeroizes the byte buffer in
  `finally`.
- `prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential()`
  uses the same credential-boundary pattern for restore authorization.
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
  still carries `prfFirstB64u` for HSS setup because the HSS client input and
  output-mask derivation still require the passkey recoverable secret.

Final shape:

```ts
export async function prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential(args: {
  authorizationPort: ThresholdEd25519PasskeyMaterialSealAuthorizationPort;
  bindingInput: ThresholdEd25519WorkerMaterialBindingInputWithoutVerifier;
  rpId: string;
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
  expiresAtMs: number;
}): Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult>;
```

The seal helper extracts PRF.first from `credential`, decodes it to
`Uint8Array`, calls
`prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization`, and zeroizes
the byte buffer in `finally`. The helper must not accept `prfFirstB64u`,
`prfFirstBytes`, or a generic secret-source object from callers.

Allowed PRF.first string boundaries after this slice:

- passkey/platform credential collection and normalization
- HSS setup code that must derive HSS client inputs or an HSS output mask
- ECDSA-HSS setup and export paths that still explicitly require PRF.first
- tests/type fixtures that assert rejection

Disallowed after this slice:

- passing `prfFirstB64u` into Ed25519 material authorization helpers
- storing PRF.first in warm-session, sealed-session, or signing-flow records
- reading PRF.first in NEAR transaction, NEP-413, delegate, or presign-pool
  signing flows

Completed in this slice:

1. `prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential()`
   no longer accepts `prfFirstB64u`.
2. Registration, add-signer, warm-session bootstrap, and HSS setup callers pass
   only `credential` into that issuer helper.
3. A source guard fails if `prepareThresholdEd25519PasskeyMaterial*`
   authorization helpers accept or receive `prfFirstB64u`.
4. Unit coverage proves the seal helper extracts PRF.first from the credential,
   passes only bytes to the worker issuer, and zeroizes the transient byte
   buffer in `finally` when the worker issuer succeeds or throws.

Remaining constraints:

1. Keep `prfFirstB64u` local to HSS client-input/output-mask setup until the
   final `clientOutputMaskB64u` cleanup lands.
2. Add type fixtures rejecting core setup/restore inputs that carry
   `prfFirstB64u`, `prfFirstBytes`, or derived seal/unseal key bytes outside the
   credential-boundary helper request types.

### 2. Email OTP Direct Restore

Current state:

- `packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource.ts`
  owns recovery-code material authorization helpers.
- `prepareRecoveryCodeSealAuthorizationForEmailOtp()` and
  `prepareRecoveryCodeUnsealAuthorizationForEmailOtp()` already decode
  `recoveryCodeSecret32B64u`, pass `Uint8Array` bytes to the near-signer worker,
  and zeroize the byte buffer.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts`
  accepts Email OTP restore only when the step-up authorization carries an
  opaque recovery-code material authorization handle with
  `kind: "recovery_code_material_authorization_handle_v1"` and
  `purpose: "unseal"`.

Final shape:

```ts
type NearEd25519EmailOtpMaterialRestoreAuthorization =
  | {
      kind: 'ed25519_email_otp_material_unseal_authorization_available';
      unsealAuthorization: NearEd25519EmailOtpRecoveryCodeUnsealAuthorization;
    }
  | {
      kind: 'ed25519_email_otp_material_unseal_authorization_unavailable';
      reason: 'no_recovery_code_material' | 'not_restore_available';
    };

type NearEd25519EmailOtpRecoveryCodeUnsealAuthorization = Extract<
  ThresholdEd25519WorkerMaterialCredentialAuthorization,
  { kind: 'recovery_code_material_authorization_handle_v1' }
> & {
  purpose: 'unseal';
};
```

The Email OTP confirmation boundary, not the NEAR signing flow, must issue this
authorization. The signing flow may carry the opaque `unsealAuthorization`
result, but it must never carry `recoveryCodeSecret32B64u`,
`recoveryCodeSecret32`, an OTP code-derived secret, or a derived unseal key.

Required callchain:

1. Email OTP step-up completes account authorization through the existing
   challenge flow.
2. If the selected Ed25519 record is `restore_available`, the Email OTP
   credential/recovery boundary obtains fresh recovery-code material or a
   worker-owned equivalent capability.
3. That boundary calls `prepareRecoveryCodeUnsealAuthorizationForEmailOtp()`
   with `materialBindingDigest`, `authSubjectId`,
   `recoveryCodeBindingDigestForEmailOtpMaterial()`, and a short expiry.
4. The boundary returns only a prepared unseal authorization branch to the NEAR
   signing step-up result.
5. `resolveRouterAbEd25519WorkerMaterialRestoreAuthorizationForStepUp()` accepts
   that branch for `email_otp` and returns
   `unseal_authorization_available`.
6. `requireOrRestoreRouterAbEd25519WalletSessionState()` restores through
   `RestoreThresholdEd25519WorkerMaterial`, persists the restored handle, and
   continues into normal signing.

If Email OTP step-up cannot produce a recovery-code unseal authorization, the
signing flow must return `material_unseal_authorization_required` before Router
A/B signing starts. It must not run HSS as a fallback.

Email OTP direct restore is therefore a conditional capability, not a silent
repair path. A normal OTP challenge proves account control, but it does not
itself recreate the durable MPC material unseal secret. The Email OTP boundary
must have either fresh recovery-code material from the current confirmation flow
or a worker-owned recovery-code authorization capability minted by that flow. If
neither exists, the caller should surface a recovery/material authorization
prompt instead of attempting HSS or continuing into signing.

The worker-owned recovery-code authorization capability is stored only in the
near-signer worker credential-authorization registry, keyed by an opaque handle
returned from `prepareRecoveryCodeUnsealAuthorizationForEmailOtp()`. It is never
stored in IndexedDB, persisted session records, route bodies, warm-session read
models, or signing-flow state as a durable capability.

`recoveryCodeBindingDigestForEmailOtpMaterial()` must return a base64url
SHA-256 digest of canonical JSON from `alphabetizeStringify()` over:

```ts
{
  kind: 'email_otp_ed25519_recovery_code_binding_v1',
  authSubjectId,
  rpId,
  nearAccountId,
}
```

It must not expose a raw colon-joined identity string. This avoids delimiter
ambiguity and keeps scoped account identifiers out of authorization handles,
logs, and diagnostics.

The registry entry must be scoped to:

- purpose: `unseal`
- `authSubjectId`
- `materialBindingDigest`
- `recoveryCodeBindingDigest`
- current `thresholdSessionId`
- current `signingGrantId`
- `expiresAtMs`
- remaining uses, with v1 fixed to one use

A replay against a different material record, recovery-code binding, threshold
session, signing grant, auth subject, or purpose must fail with
`material_unseal_authorization_required`.

Implementation constraints:

- Do not add `recoveryCodeSecret32B64u` to `NearEd25519StepUpAuthorization`.
- Do not derive recovery-code material in `flows/signNear/**`.
- Keep `prepareRecoveryCodeUnsealAuthorizationForEmailOtp()` as the only SDK web
  helper that constructs
  `ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest`.
- Require the available Email OTP restore branch to carry
  `kind: "recovery_code_material_authorization_handle_v1"` and
  `purpose: "unseal"` at the TypeScript type and shared resolver parser.
- Map `no_recovery_code_material` to
  `material_unseal_authorization_required` in signing readiness.
- Treat `not_restore_available` as a typed non-applicable branch. It should be a
  no-op for records that are already loaded/signable or do not have sealed
  material to restore.
- Add a source guard that fails if `flows/signNear/**`,
  `session/persistence/**`, route clients, warm-session read models, or Router
  A/B signing helpers contain `recoveryCodeSecret32` or
  `recoveryCodeSecret32B64u`.
- Add a unit test where an Email OTP `restore_available` Ed25519 record receives
  an opaque recovery-code unseal authorization and reaches
  `persistStoredThresholdEd25519SessionMaterialHandle()` before signing.
- Add a negative unit test where an Email OTP `restore_available` Ed25519 record
  without the authorization fails with
  `material_unseal_authorization_required`.
- Add a replay negative test where a recovery-code unseal handle minted for one
  session, signing grant, recovery-code binding, or material binding is rejected
  for another.

### 3. Final `clientOutputMaskB64u` Cleanup

Current state:

- `StoreThresholdEd25519WorkerMaterialFromHssOutput` now consumes
  `clientOutputMask` as a one-use Rust-owned `clientOutputMaskHandle` in
  signer-core command types, near-signer WASM, SDK worker request types, and the
  SDK near-signer wrapper.
- `clientOutputMaskB64u` remains only in HSS setup/opening boundary code, most
  notably the HSS client-owned staged evaluator artifact path. It is no longer a
  final worker-material store command field and is not used as a durable sealing
  secret.

Final shape:

```ts
type ThresholdEd25519HssClientOutputMaskTransport =
  | {
      kind: 'worker_local_mask_bytes_v1';
      clientOutputMaskBytes: Uint8Array;
    }
  | {
      kind: 'rust_owned_mask_handle_v1';
      clientOutputMaskHandle: string;
    };

export type ThresholdEd25519StoreWorkerMaterialFromHssOutputRequest = {
  evaluatorDriverStateB64u: string;
  clientOutputMessageB64u: string;
  clientOutputMask: ThresholdEd25519HssClientOutputMaskTransport;
  expectedContextBindingB64u: string;
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: number[];
  createdAtMs: number;
  sealAuthorization: ThresholdEd25519WorkerMaterialSealAuthorization;
};
```

Implementation steps:

1. Completed: in `crates/signer-core/src/commands/ed25519_worker_material.rs`, replace
   `client_output_mask_b64u: String` with either byte-capable worker-local mask
   transport or a one-use Rust-owned `clientOutputMaskHandle`.
2. Completed: regenerate
   `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts`.
3. Completed for worker-material store: update
   `wasm/near_signer/src/threshold/worker_material.rs` and
   `wasm/near_signer/src/threshold/threshold_hss.rs` store/open paths to consume
   mask bytes or consume a one-use mask handle, then zeroize the mask after
   opening the HSS output.
4. Completed: update
   `packages/sdk-web/src/core/signingEngine/chains/near/nearSignerWasm.ts` and
   worker request types to pass the mask transport branch.
5. Prefer the one-use Rust-owned handle for generated or serialized command
   paths. Use the byte branch only after a focused test proves the request
   crosses `postMessage`/worker boundaries through structured clone or direct
   worker-local calls and never through JSON serialization.
6. Update HSS setup wrappers to decode the current mask string only at the HSS
   setup boundary while the transitional field still exists. The final slice
   deletes the decode step by returning either a byte-capable worker-local value
   or a one-use handle from HSS mask derivation.
7. Completed: delete `clientOutputMaskB64u` from final command shapes and generated
   worker-material request types.
8. Remaining: keep `clientOutputMaskB64u` only in HSS client-output setup and
   staged-artifact boundary code until those paths are rewritten around the same
   byte-capable worker-local transport or Rust-owned handle.

Acceptance guards:

- `packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts` does not
  contain `clientOutputMaskB64u`.
- `packages/sdk-web/src/core/types/signer-worker.ts` does not contain
  `clientOutputMaskB64u` in worker-material store request types.
- `flows/signNear/**`, unlock, signing surface, warm-session read models, and
  persistence files contain no `clientOutputMaskB64u`.
- A focused serialization test proves the selected mask transport does not
  stringify mask bytes. If that proof is missing, the final command must use the
  one-use Rust-owned handle branch.

### 4. Add-Signer And Device-Sync Setup

Current state:

- Registration stores sealed Ed25519 worker material through
  `StoreThresholdEd25519WorkerMaterialFromHssOutput`.
- Add-signer Ed25519 setup in
  `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts` still
  follows the start/respond/finalize HSS path and must persist the same durable
  worker-material facts as registration.
- Server add-signer route cores still include unimplemented branches in some
  environments, so this SDK slice must follow the current route contract instead
  of adding a second setup protocol.

Final shape for every Ed25519 setup path:

1. Prepare HSS client inputs.
2. Prepare a credential-scoped `sealAuthorization`.
3. Run the server HSS prepare/respond/finalize route sequence.
4. Store HSS output with
   `StoreThresholdEd25519WorkerMaterialFromHssOutput`.
5. Reuse the registration material format: same `materialKeyId` construction,
   material binding digest canonicalization, sealed artifact AAD, sealing
   primitive, and persistence write shape.
6. Persist `sealedWorkerMaterialRef`, `sealedWorkerMaterialB64u`,
   `materialFormatVersion`, `materialBindingDigest`, `materialKeyId`,
   `materialCreatedAtMs`, `signerSlot`, `keyVersion`,
   `clientVerifyingShareB64u`, and the loaded `materialHandle` hint.
7. Publish warm-session authorization separately from material readiness.

Implementation steps:

- Extract the registration persistence write shape into a small helper only if
  add-signer and registration need the exact same object construction. Keep the
  helper in the registration/session setup area, not in normal signing flows.
- Add-signer and device-sync must call the same material write helper as
  registration once that helper exists. They must not define a second sealed
  artifact shape, AAD shape, or material-binding canonicalization path.
- Add-signer must use the same
  `prepareThresholdEd25519PasskeyMaterialSealAuthorizationFromCredential()`
  boundary as registration.
- Device-sync/add-device may run HSS only when it is explicitly creating or
  syncing durable key material. Normal unlock or transaction signing must not
  use those setup helpers.
- Add source guards proving add-signer and device-sync setup can call HSS setup
  helpers, while unlock and normal signing cannot.
- Add unit coverage proving add-signer Ed25519 finalize persists sealed worker
  material facts and never persists `xClientBaseB64u`.

### 5. HSS-Named Helper Cleanup

Do this after passkey, Email OTP, add-signer, and `clientOutputMaskB64u` cleanup
are stable. This is the last Refactor 74 cleanup slice and must be naming-only.
It may rename symbols/files, update imports, and update guards/tests. It must
not change worker command payloads, restore behavior, persistence parsing, HSS
route use, or policy decisions.

Rename only helpers whose active behavior is worker-material validation or
restore. Keep HSS in names that actually run an HSS ceremony.

Rename map:

- `requireThresholdEd25519HssSigningMaterialHandle` ->
  `requireThresholdEd25519WorkerMaterialHandle`
- `workerMaterialHandle.ts` owns loaded worker-material validation.
- `hssClientBase.ts` contains only real HSS derivation constants.
- `hssMaterialBinding.ts` has been renamed to `workerMaterialBinding.ts`; tests
  now import the worker-material package-output path directly.
- `RouterAbEd25519SigningMaterialRef` keeps field names
  `materialHandle`, `bindingDigest`, and `clientVerifierB64u`.
- `runThresholdEd25519HssCeremonyWithMaterialHandle` ->
  `runThresholdEd25519HssCeremonyAndStoreWorkerMaterial`

Completed active record rename:

- `ed25519HssMaterialHandle` -> `ed25519WorkerMaterialHandle`
- `ed25519HssMaterialBindingDigest` -> `ed25519WorkerMaterialBindingDigest`

The active record rename was one isolated mechanical slice with a source guard
rejecting the old active field names. Type fixtures should continue rejecting
material fields in invalid branches. Do future file renames after semantic
cleanup so it does not collide with material restore work.

### 6. Required Test And Guard Matrix

Add or keep these checks with each slice:

- Source guard: normal Ed25519 unlock/signing cannot call
  `runThresholdEd25519HssCeremonyWithMaterialHandle`,
  `runThresholdEd25519HssCeremonyAndStoreWorkerMaterial`, HSS route clients, or
  direct HSS reconstruction helpers.
- Source guard: `flows/signNear/**` cannot contain `prfFirstB64u`,
  `prfFirstBytes`, `recoveryCodeSecret32`, `recoveryCodeSecret32B64u`,
  `clientOutputMaskB64u`, or `xClientBaseB64u`.
- Source guard: only credential-boundary modules can construct
  `ThresholdEd25519PreparePasskeyPrfWorkerMaterial*AuthorizationRequest` or
  `ThresholdEd25519PrepareRecoveryCodeWorkerMaterial*AuthorizationRequest`.
- Type fixtures: current sealed-session and active session records reject raw
  Ed25519 client material.
- Type fixtures: core setup/restore functions reject raw PRF strings,
  recovery-code secret strings, and derived seal/unseal key bytes.
- Rust/TypeScript vectors: material key id, material binding digest, session
  binding digest, and sealed artifact AAD must match byte-for-byte.
- Rust crypto negatives: wrong AAD, wrong unseal secret, wrong material binding,
  corrupt ciphertext, wrong nonce length, verifier mismatch, session grant
  mismatch, worker mismatch, and expiry all fail closed.

## Phase 1C: Clean Credential-Boundary Authorization Issuer

This phase replaces the current transitional PRF/recovery-material bridge with
the final issuer architecture above by wrapping existing near-signer material
authorization and binding helpers.

- [x] Add prepared seal issuer request/result types for
      `Ed25519PrepareWorkerMaterialSealAuthorizationRequest` and
      `Ed25519PreparedWorkerMaterialSealAuthorization`. Reuse existing material
      authorization handle types and keep the seal branch scoped to stable
      `materialKeyId` before the durable artifact digest exists.
- [x] Add prepared unseal issuer request/result types for
      `Ed25519PrepareWorkerMaterialUnsealAuthorizationRequest` and
      `Ed25519PreparedWorkerMaterialUnsealAuthorization`. Reuse the existing
      `materialBindingDigest`-scoped unseal authorization handle type.
- [x] Implement the seal issuer as a thin near-signer wrapper over existing
      material key-id construction and passkey/recovery-code material
      authorization installation. It must return only `materialKeyId` plus the
      opaque `seal` handle.
- [x] Implement the unseal issuer as a thin near-signer wrapper over existing
      passkey/recovery-code material authorization installation for an existing
      `materialBindingDigest`. It must return only the existing opaque
      `unseal` handle.
- [x] Update `StoreThresholdEd25519WorkerMaterialFromHssOutput` SDK wrappers to
      pass verifier-free public binding facts plus the prepared
      `materialKeyId`-scoped seal authorization. Store opens HSS output,
      derives the final verifier, computes `materialBindingDigest`, and rejects
      a seal handle whose `materialKeyId` does not match.
- [x] Change the material-handle HSS ceremony wrapper to accept an already
      prepared `sealAuthorization` result instead of raw passkey PRF or
      recovery-code source material.
- [x] Change final `StoreThresholdEd25519WorkerMaterialFromHssOutput` command
      wrappers to pass byte-capable worker-local mask transport or a one-use
      Rust-owned mask handle. Delete `clientOutputMaskB64u` from final command
      types after transitional generated wrappers are replaced.
- [x] Delete the setup dependency on
      `deriveThresholdEd25519ClientVerifyingShareFromPrfFirst()` from
      `hssLifecycle.ts`, `thresholdWarmSessionBootstrap.ts`, and email-OTP
      provisioning. Keep only public-diagnostic verifier derivation if a
      non-signing caller still needs it.
- [x] Move passkey PRF extraction to the passkey/platform credential boundary:
      extract PRF.first as raw bytes, transfer those bytes to the issuer
      command, zeroize the transient view, and return only the material
      authorization result.
- [x] Move passkey Ed25519 prepared seal/unseal issuer construction, PRF decode,
      and zeroization out of HSS lifecycle, warm-session bootstrap, and signing
      restore code into the passkey material-authorization boundary module.
- [x] Move Email OTP Ed25519 material derivation to the email/recovery worker
      boundary: expose `recoveryCodeSecret32` only as a transient
      `Uint8Array` issuer input, and delete `prfFirstB64u` naming from
      Ed25519 email-account material setup/restore code.
- [x] Move Email OTP Ed25519 recovery-code seal authorization construction,
      recovery-code secret decode, and zeroization out of SDK provisioning into
      the Email OTP material-authorization boundary module.
- [x] Rename the Email OTP Ed25519 reconstruction API and active call sites
      from `prfFirstB64u` to `recoveryCodeSecret32B64u`, and add a source
      guard preventing the old field from returning to
      `session_ed25519_reconstruction` inputs.
- [x] Replace the old direct warm-session PRF claim path and passkey PRF cache
      callers used by normal Ed25519 restore with issuer calls that return
      `Ed25519PreparedWorkerMaterialUnsealAuthorization`.
- [x] Isolate the transitional PRF claim in a single passkey unseal-issuer
      boundary so the worker-material restore path consumes only a prepared
      `unsealAuthorization`.
- [x] Narrow normal Ed25519 signing-material restore inputs so passkey restore
      receives a passkey unseal-authorization issuer instead of a
      `signingSessionCoordinator` capability that can return raw PRF material.
- [x] Move the transitional passkey unseal issuer implementation from the NEAR
      signing restore helper into the passkey material-authorization boundary
      module.
- [x] Implement passkey warm-session unseal-handle hardening. Unlock can install
      a one-use opaque Ed25519 material unseal authorization when the same
      passkey assertion already produced PRF material and a restoreable sealed
      Ed25519 artifact exists. Unlock still does not restore worker material and
      still succeeds when the handle cannot be installed.
- [x] Require every prepared issuer call site to receive an already
      server-authorized setup, repair, or step-up context. The issuer must not
      make signing policy decisions and must not mint signing authority.
- [x] Add source guards proving active Ed25519 setup, restore, warm-session
      hydration, and signing code outside credential-boundary adapters cannot
      read identifiers named `prfFirstB64u`, `prfFirstBytes`,
      `recoveryCodeSecret32`, `recoveryCodeSecret32B64u`, or raw PRF/recovery
      material.
- [x] Add source guards proving SDK worker operation maps and the generated
      near-signer package do not expose direct material install request
      variants.
- [x] Add source guards proving only credential-confirm boundary adapters can
      construct `Ed25519PrepareWorkerMaterial*AuthorizationRequest` or private
      install request objects that carry `prfFirstBytes` or
      `recoveryCodeSecret32`.
- [x] Add source guards proving prepared issuer calls do not bypass server
      Wallet Session, Signing Grant, server-authoritative budget, route
      authorization, or step-up authorization checks.
- [x] Add source guards proving `clientOutputMaskB64u` does not appear in final
      worker command shapes and is used only in transitional HSS output
      boundary decoding code.
- [x] Add source guards proving `deriveThresholdEd25519ClientVerifyingShareFromPrfFirst`
      is not called by setup, restore, unlock, or signing flows.
- [x] Add worker tests proving the seal issuer returns a stable `materialKeyId`
      authorization, that store consumes by `materialKeyId`, and that a
      mismatched key id is rejected before sealing.
- [x] Add worker tests proving unseal issuer handles are single-use, scoped to
      one `materialBindingDigest`, expire, and reject purpose mismatches.
- [x] Add worker tests proving v1 `seal` and `unseal` handles default to one
      use, clamp or reject non-`1` `maxUses`, default to 60 seconds, and reject
      expiries above the 5-minute cap unless a typed server-authorized
      capability branch permits them.
- [x] Add SDK wrapper tests proving prepared issuer results contain only public
      material facts plus opaque handles and never include PRF/recovery secret
      fields.
- [x] Add type fixtures rejecting core setup/restore function inputs that carry
      raw PRF strings, recovery-code secret strings, or derived seal/unseal key
      bytes.

## Phase 2: Remove Ed25519 HSS From Unlock

- [x] Delete the `prewarmEd25519MaterialForWarmup()` call from both unlock
      branches in `login.ts`.
- [x] Delete `prewarmThresholdEd25519ClientBaseFromCredential` and all active
      login, registration, session-bootstrap, and signing-surface call paths.
- [x] Keep `primeThresholdLoginWarmSigners()` responsible for minting or
      restoring Wallet Session authorization.
- [x] Restore passkey Ed25519 worker material during unlock only through the
      sealed worker-material restore path for the exact minted threshold session.
- [x] Preserve ECDSA warm-session bootstrap behavior only where it is required
      to mint the selected ECDSA session.
- [x] Update unlock events so `STEP_05_ED25519_SIGNING_SESSION_READY` means
      authorization ready. Rename the event if callers need visible distinction
      between authorization and material readiness.

## Phase 3: Replace Unlock Postconditions

- [x] Split `assertPasskeyUnlockRuntimePostconditions()` into an unlock
      authorization postcondition and a signing-material postcondition.
- [x] Make unlock validate active session id, signing grant id,
      Wallet Session auth, expiry, budget, auth method, and lane scope.
- [x] Allow Ed25519 `material_pending` during unlock.
- [x] Keep the passkey unlock postcondition authorization-ready rather than
      sign-ready, so missing worker material stays a modeled pending state.
- [x] Keep registration and explicit signing checks strict about material
      readiness.
- [x] Stop using `readPersistedAvailableSigningLanes()` as the Ed25519 unlock
      postcondition because it currently models sign-ready lanes.
- [x] Add unit coverage for Ed25519 unlock success with `material_pending`.
- [x] Add unit coverage proving Ed25519 signing still materializes or rejects
      before any signature is produced.

## Phase 4: Keep Lazy Materialization In The Sign Path

- [x] Transaction planning already treats passkey Ed25519 `material_pending` as
      sign-plannable when the warm session has enough remaining uses.
- [x] Replace the transaction `pending_material` HSS repair branch with a
      shared fail-closed material-restore-required branch.
- [x] Replace that shared `pending_material` branch with
      `requireOrRestoreRouterAbEd25519WalletSessionState()`.
- [x] Make that helper validate a loaded handle first, restore through
      `RestoreThresholdEd25519WorkerMaterial` when `sealedWorkerMaterialRef`
      exists, and return `material_restore_required` when the sealed artifact is
      missing.
- [x] Return `material_unseal_authorization_required` when the artifact exists
      and no active credential-scoped unseal authorization handle is available.
- [x] Prepare a passkey credential-scoped unseal authorization handle in NEAR
      transaction, NEP-413, and delegate signing when the current Ed25519 record
      is `restore_available` and the signing step-up already produced a passkey
      credential.
- [x] Remove the old direct PRF claim call from the direct
      material-resolver / Ed25519 HSS reconstruction branch.
- [x] Remove daily-signing calls to `ensureThresholdEd25519HssSigningMaterial()`.
- [x] Reuse an already loaded worker handle when the near-signer worker material
      registry validates the persisted handle hint.
- [x] Delete the TypeScript raw-client-base cache path from the target signing
      flow and keep transaction repair on the worker-owned restore path.
- [x] Replace `validateThresholdEd25519HssMaterialHandleWasm()` with
      `validateThresholdEd25519WorkerMaterialWasm()` after the Rust-owned
      registry lands.
- [x] Build `Ed25519WorkerMaterialSessionBindingV1` in the shared restore helper
      and pass it to create-presign/sign-presign worker commands.
- [x] Delete `thresholdEd25519HssMaterialByHandle` and
      `StoredEd25519HssMaterial` from `near-signer.worker.ts`.
- [x] Add a signer-core-owned sealed material restore command and route only
      opaque restore artifacts through TypeScript.
- [x] Replace deterministic HSS material handles with random worker-local
      material handles and persist them as validation hints only.
- [x] Delete raw client-base persistence fields after worker-owned restore
      lands and boundary parsers prune stale records.
- [x] Persist the restored material handle after worker restore.
- [x] Refresh the sealed record after worker restore in the transaction, NEP-413,
      and delegate signing paths.
- [x] Add pending-material fail-closed parity for NEP-413 message signing.
- [x] Add pending-material fail-closed parity for NEP-461 delegate-action
      signing.
- [x] Replace NEP-413 and delegate fail-closed parity with the same shared
      signer-core-owned material loader used by NEAR transaction signing.
- [x] Route Ed25519 Router A/B normal-signing pool misses through a foreground
      presign-pool refill and the near-signer worker-owned presign path.
- [x] Delete the stale HSS client worker direct client-share fallback from
      Ed25519 Router A/B normal signing.
- [x] Replace passkey Ed25519 reconnect material prewarm with exact-session
      sealed worker-material restore and fail closed when reconnect cannot
      produce signable Router A/B material.
- [x] Add tests proving NEAR transaction, NEP-413, and delegate signing all use
      the same worker-owned material restore path and never invoke HSS during
      normal signing.
- [x] Add a focused test proving normal signing prepares a passkey unseal
      authorization through the credential-boundary issuer and zeroizes the
      transient PRF byte buffer after the worker call.
- [x] Wire recovery-code unseal authorization into an Email OTP direct restore
      path if Email OTP signing stops minting fresh material through its existing
      per-operation confirmation path.
- [x] Narrow Email OTP direct restore to recovery-code `unseal` authorization
      handles at the NEAR step-up type and shared restore resolver parser.

Current note: NEAR transaction, NEP-413, and delegate signing now route through
`requireOrRestoreRouterAbEd25519WalletSessionState()`. A shared restore
authorization resolver prepares a passkey unseal handle only when the current
record is `restore_available` and the signing step-up has a passkey credential.
For Email OTP, the resolver accepts only an opaque recovery-code `unseal`
authorization handle supplied by the credential/recovery boundary. The helper
validates an already loaded worker handle first, restores sealed worker material
when the caller supplies a credential-scoped unseal authorization handle,
persists the restored handle plus material binding metadata, refreshes passkey
sealed restore metadata, and returns
`material_unseal_authorization_required` before signing when no active unseal
authorization is available. Ed25519 Router A/B normal signing now uses the
near-signer worker-owned presign path for both pool hits and foreground
pool-miss refills; the stale HSS client worker direct-share fallback is gone.
Passkey unlock and passkey reconnect no longer call the HSS prewarm helper:
unlock restores sealed worker material for the exact minted threshold session
when possible while preserving `material_pending` as an authorization-ready
state, and reconnect requires exact-session sealed worker-material restore
before returning a refreshed record for immediate signing.
The remaining implementation work is legacy HSS client-worker raw client-base
cleanup, legacy HSS staged-artifact output-mask boundary cleanup, missing type
fixtures/guards, and broader end-to-end signing evidence.

Registration/unlock remint acceptance:

- [x] A persisted Ed25519 material handle is only a durable hint. It is signable
      only after the near-signer worker validates the handle against the current
      Wallet Session JWT, signing grant id, threshold session id, signing root
      id/version, runtime-policy scope, SigningWorker id, client verifier, and
      material binding digest.
- [x] If unlock remints session auth and the persisted handle cannot be validated
      for that exact current binding, the record must classify as
      `restore_available` when sealed worker material exists. If no sealed artifact
      exists, it must classify as `material_pending` / `material_restore_required`.
- [x] Unlock success means authorization-ready. Signing readiness is a separate
      runtime-validated state.
- [x] Final signing consumes only validated worker-owned material. It must not
      restore, claim PRF output, run HSS, or fall back.
- [x] Regression coverage must prove that registration persists worker-material
      facts, unlock remints or refreshes Wallet Session auth, the classifier returns
      validated `signable` or explicit `restore_available` / `material_pending`,
      and Refactor 70 budget evidence does not start counting signatures until
      Ed25519 material readiness has been validated or restored.

## Phase 5: Optional Warm-Session Unseal Handle Hardening

This phase replaces the passkey Ed25519 restore-facing warm-session PRF claim
with a narrower opaque Ed25519 material `unseal` authorization handle. The
passkey path is implemented. The Email OTP/recovery-code unlock install remains
an optional future extension because normal Email OTP unlock does not carry
recovery-code material.

Unlock must still finish as authorization-ready, not signing-material-ready.
This phase must not restore worker material during unlock, must not make unlock
depend on material restoration, and must not call Ed25519 HSS.

Implemented facts:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts` classifies the exact
  Ed25519 persisted record for the connected threshold session after wallet
  authorization succeeds. When the record is `restore_available`, passkey unlock
  prepares a scoped `unseal` authorization from the same WebAuthn assertion and
  stores it in the credential-confirm worker.
- `packages/sdk-web/src/core/types/secure-confirm-worker.ts` and
  `packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
  expose Ed25519-specific put/claim commands. The worker stores only the opaque
  authorization plus public scope fields, consumes successful claims, and clears
  expired, exhausted, or mismatched entries.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts`
  resolves warm-session restore by claiming that opaque authorization. It no
  longer asks Ed25519 restore code to claim PRF.first.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialAuthPlan.ts`
  keeps `restore_available` on the warm-session auth plan so the first signing
  operation can try the installed handle before prompting for a fresh passkey
  step-up.
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
  no longer exports the Ed25519 warm-session PRF claim helpers.

So a passkey user should not see a second prompt immediately after unlock when
the sealed Ed25519 artifact exists, the passkey assertion produced PRF material,
and the installed unseal handle is still live. If that prompt happens, treat it
as a bug in the install, claim, restore, or planning path.

### Replacement Contract

This phase replaces the Ed25519 restore-facing warm-session PRF claim. It must
not add a second fallback path.

Current Ed25519 restore contract:

```ts
claimWarmSessionPrfFirst(...)
  -> prfFirstB64u
  -> prepareThresholdEd25519PasskeyMaterialUnsealAuthorizationFromCredential(...)
  -> RestoreThresholdEd25519WorkerMaterial
```

Target Ed25519 restore contract:

```ts
claimWarmSessionEd25519UnsealAuthorization(...)
  -> ThresholdEd25519WorkerMaterialCredentialAuthorization
  -> RestoreThresholdEd25519WorkerMaterial
```

After this phase, normal Ed25519 restore code must not receive, decode, name,
or rewrap PRF.first. It receives only an opaque prepared `unseal`
authorization already scoped by signer-core/WASM to the exact sealed material
artifact. ECDSA HSS setup/export material remains outside this phase; any
remaining `prfFirstB64u` for ECDSA must stay in explicitly named ECDSA/HSS
boundary files.

The implemented passkey behavior is:

1. Unlock obtains server-authorized Wallet Session and Signing Grant state.
2. Unlock reads the exact Ed25519 sealed material metadata for the current
   wallet, auth method, signing grant, and threshold session.
3. If that metadata classifies as `restore_available` and the credential
   boundary already has fresh passkey PRF material from the unlock ceremony, the
   credential boundary installs a one-use `unseal` authorization handle scoped
   to that material artifact.
4. Unlock stores only the opaque handle in the volatile credential-confirm
   worker store.
5. Unlock completes even when no handle is installed.
6. The first Ed25519 signing operation consumes the installed handle to restore
   worker material without prompting again, then proceeds through the normal
   Router A/B budget and signing path.

This is different from background restore. Warm-session unseal handles only
cache a local unseal capability for later use. They do not load worker material,
create presignatures, reserve budget, or produce signatures.

### Target State

Represent the installed handle as a narrow lifecycle union. Core signing code
must not accept a loose optional handle bag.

```ts
type Ed25519WarmSessionUnsealAuthorization =
  | {
      kind: 'none';
      reason:
        | 'no_restore_artifact'
        | 'credential_material_unavailable'
        | 'unsupported_auth_method'
        | 'install_failed';
    }
  | {
      kind: 'installed';
      authorization: ThresholdEd25519WorkerMaterialCredentialAuthorization & {
        purpose: 'unseal';
      };
      walletId: string;
      authMethod: 'passkey' | 'email_otp';
      signingGrantId: string;
      thresholdSessionId: string;
      materialBindingDigest: string;
      expiresAtMs: number;
      maxUses: 1;
    };
```

The `installed` branch must be created by a credential-boundary adapter. The
adapter is the only code allowed to touch passkey PRF bytes or recovery-code
secret bytes. SDK session, persistence, route-client, and signing code may only
receive the opaque `authorization` result plus public identity fields. This
replaces the old `prfFirstB64u` warm-session material claim contract for
Ed25519 restore; ECDSA HSS setup/export material remains a separate boundary
concern.

### Worker Boundary Commands

The implementation uses Ed25519-specific worker commands instead of overloading
the generic warm-session material commands:

```ts
type WarmSessionEd25519UnsealAuthorizationPut = {
  type: 'WARM_SESSION_ED25519_UNSEAL_AUTHORIZATION_PUT';
  payload: {
    sessionId: string;
    signingGrantId: string;
    walletId: string;
    authMethod: 'passkey' | 'email_otp';
    materialBindingDigest: string;
    authorization: ThresholdEd25519WorkerMaterialCredentialAuthorization;
    expiresAtMs: number;
    remainingUses: 1;
  };
};

type WarmSessionEd25519UnsealAuthorizationClaim = {
  type: 'WARM_SESSION_ED25519_UNSEAL_AUTHORIZATION_CLAIM';
  payload: {
    sessionId: string;
    signingGrantId: string;
    walletId: string;
    authMethod: 'passkey' | 'email_otp';
    materialBindingDigest: string;
    consume: true;
  };
};
```

The claim result must be a typed union:

```ts
type WarmSessionEd25519UnsealAuthorizationClaimResult =
  | {
      ok: true;
      authorization: ThresholdEd25519WorkerMaterialCredentialAuthorization;
      expiresAtMs: number;
    }
  | {
      ok: false;
      code:
        | 'not_found'
        | 'expired'
        | 'exhausted'
        | 'scope_mismatch'
        | 'invalid_authorization'
        | 'worker_error';
    };
```

The worker must reject claims when `sessionId`, `signingGrantId`, `walletId`,
`authMethod`, or `materialBindingDigest` differs from the installed scope.
Successful claims consume the entry. Failed claims caused by expiry, exhaustion,
or mismatch also clear the entry.

The old `WARM_SESSION_MATERIAL_*` commands may remain only for ECDSA HSS
setup/export boundaries. They must not be used by Ed25519 worker-material
restore after this phase.

### Scope And Lifetime

A warm-session unseal handle must be:

- one-use by default;
- short lived, with the same default 60-second TTL and 5-minute cap as other
  credential authorization handles;
- volatile memory only;
- scoped to `purpose: 'unseal'`;
- scoped to the exact `walletId`, `authMethod`, `signingGrantId`,
  `thresholdSessionId`, and `materialBindingDigest`;
- cleared on logout, active wallet change, active signing-grant replacement,
  threshold-session remint, auth-method switch, credential-confirm volatile
  material clear/reset, or first consume;
- rejected if any current signing-session identity field differs from the
  fields captured when the handle was installed.

A near-signer worker reset invalidates the Rust-owned authorization handle
referenced by the cached authorization object. After that, a later stale claim
must fail closed as `material_unseal_authorization_required` and require fresh
step-up authorization. The no-second-prompt guarantee applies to the same
unlock runtime while the installed Rust-owned handle remains live.

The handle is not a durable restore artifact. It must never be written to
IndexedDB, sealed-session records, route request bodies, logs, or diagnostics
objects. Diagnostics may report only branch names such as
`warm_session_unseal_handle_installed` or
`warm_session_unseal_handle_absent`.

### Passkey Flow

Passkey unlock may install the handle only when the same WebAuthn assertion
already produced PRF output for the correct credential scope.

1. The passkey credential boundary extracts PRF.first from the assertion.
2. The boundary calls the existing prepared unseal issuer with the current
   `materialBindingDigest`.
3. The boundary zeroizes the transient byte view in `finally`.
4. The boundary returns only `Ed25519PreparedWorkerMaterialUnsealAuthorization`
   and public identity facts.
5. Unlock stores the opaque authorization in the volatile credential-confirm
   worker store.

If PRF output is absent, unsupported, expired, or rejected by the worker, unlock
records the `none` branch and still succeeds.

### Email OTP / Recovery Flow Future Extension

Email OTP unlock may install the handle only when recovery-code material is
already present inside the email/recovery credential boundary. Email OTP account
control alone is insufficient for Ed25519 material unsealing. The current
implementation supports opaque recovery-code unseal authorization for signing
restore after step-up; it does not install a recovery-code unseal handle during
normal Email OTP unlock because that flow does not collect recovery-code
material.

1. The email/recovery boundary receives recovery-code material as transient
   bytes.
2. The boundary calls the prepared recovery-code unseal issuer for the current
   `materialBindingDigest`.
3. The boundary zeroizes the transient byte view in `finally`.
4. Unlock stores only the opaque `unseal` authorization result.

If the user has not provided recovery-code material during unlock, the branch is
`none` with `reason: 'credential_material_unavailable'`.

### First-Sign Consumption

`requireOrRestoreRouterAbEd25519WalletSessionState()` may consume a
warm-session unseal handle only after it validates:

- the current wallet/session identity matches the installed handle scope;
- the current record is `restore_available`;
- `sealedWorkerMaterialRef` and `materialBindingDigest` match the handle scope;
- the handle has not expired or already been consumed;
- the normal Router A/B signing prerequisites still hold.

The restore helper should prefer a fresh step-up-provided unseal authorization
when one exists for the current signing operation. If no fresh step-up handle is
present, it may use the warm-session unseal handle. After successful or failed
consume, the installed handle must be cleared from the volatile worker store.

The restore operation itself must not decrement server-authoritative signature
budget. Budget reservation and decrement occur only in the normal Router A/B
signing path after worker material is validated or restored.

The restore authorization resolution order is:

1. Use a fresh operation step-up unseal authorization when the current signing
   operation already produced one.
2. Otherwise consume the warm-session Ed25519 unseal authorization when it
   exactly matches the current session and material binding.
3. Otherwise return `material_unseal_authorization_required`.

There is no fallback from branch 2 to `claimWarmSessionPrfFirst()` for Ed25519
restore. That PRF claim path is deleted for Ed25519 once this phase lands.

### Failure Behavior

Warm-session unseal-handle installation failures are non-fatal for unlock. They
must produce a typed local result and may emit a diagnostic event. They must not
throw an unlock failure unless the underlying wallet authorization failed.

First signing behavior remains fail closed:

- stale or mismatched installed handle:
  `material_unseal_authorization_required`;
- missing installed handle and no step-up handle:
  `material_unseal_authorization_required`;
- missing sealed material artifact:
  `material_restore_required`;
- restore failure after consuming a valid handle:
  typed material restore failure, with no Router A/B signing attempt.

### Implementation Inventory

Implemented SDK touch points:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
  - classifies current Ed25519 restore metadata after Wallet Session and Signing
    Grant state are known;
  - installs a passkey credential-boundary unseal authorization when the current
    record is `restore_available`;
  - keeps unlock non-fatal when the handle is unavailable or installation fails
    locally;
  - never treats the installed handle as worker-material readiness.
- `packages/sdk-web/src/core/signingEngine/session/passkey/prfClaim.ts`
  - exposes the passkey unseal issuer that returns only an opaque prepared
    unseal authorization;
  - zeroizes transient PRF bytes in `finally`;
  - keeps remaining PRF helpers limited to credential-boundary issuer
    construction and ECDSA/HSS boundaries.
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
  - deletes the Ed25519 restore-facing `claimPasskeyEd25519PrfFirst()` and
    `restorePasskeyEd25519SessionBeforeClaim()` helpers.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialRestoreAuthorization.ts`
  - chooses fresh step-up authorization first, then validated warm-session
    authorization;
  - never returns raw PRF material to Ed25519 restore.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialAuthPlan.ts`
  - leaves `restore_available` on the warm-session plan so the installed handle
    can be consumed before fresh passkey reauth.
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
  - exposes the warm-session unseal claim method to the NEAR signing coordinator.
- `packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts` and
  `packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`
  - expose the passkey unlock install port.
- `packages/sdk-web/src/core/types/secure-confirm-worker.ts`
  - adds Ed25519-specific warm-session unseal authorization command types.
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts` and
  `packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types.ts`
  - parse and expose typed put/claim methods for the worker commands.
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
  - stores only the opaque Ed25519 unseal authorization plus public scope facts
    for Ed25519 restore;
  - consumes successful claims and clears expired, exhausted, or mismatched
    entries;
  - keeps raw PRF handle storage only in explicitly named ECDSA/HSS boundary
    paths.
- `tests/unit/refactor74LoginNoHss.guard.unit.test.ts`
  - source guards the command shape, restore resolver, auth planner, deleted PRF
    claim helpers, and raw PRF boundary classification.

Future optional touch point:

- Email OTP unlock may add a recovery-code warm-session unseal issuer only if
  that unlock ceremony collects recovery-code material. Until then, Email OTP
  direct restore remains a step-up path that receives an opaque recovery-code
  unseal authorization.

### Deletion Rules

After this phase lands:

- `ed25519Recovery.ts` must not import or call `claimWarmSessionPrfFirst`.
- `ed25519MaterialRestoreAuthorization.ts` must not decode PRF.first or call a
  helper that returns PRF.first.
- `signingSessionAuthMode.ts` may call `restorePersistedSessionForSigning()`,
  but that restore path must consume an Ed25519 unseal authorization, not a PRF
  claim.
- `WARM_SESSION_MATERIAL_CLAIM` must not appear in active Ed25519 restore
  files.
- Ed25519 restore diagnostics must not include raw PRF field names.
- Any remaining `prfFirstB64u` references must be classified as credential
  boundary, ECDSA HSS setup/export, tests for those boundaries, or obsolete and
  deleted.

Suggested grep checklist:

```sh
rg -n "claimWarmSessionPrfFirst|WARM_SESSION_MATERIAL_CLAIM|prfFirstB64u" \
  packages/sdk-web/src/core/signingEngine/session/passkey \
  packages/sdk-web/src/core/signingEngine/flows/signNear/shared \
  packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts
```

No hit in an Ed25519 restore/signing file may remain unless the line is a
source guard, a type fixture proving rejection, or an explicitly documented
credential-boundary issuer.

### Tests And Guards

- [x] Add source-guard coverage proving the replacement warm-session path can
      install a passkey unseal handle without restoring worker material during
      unlock.
- [x] Add source-guard coverage proving unlock treats warm-session handle
      installation as optional and non-fatal.
- [x] Add source-guard coverage proving first sign can consume the warm-session
      unseal handle before requesting another passkey assertion.
- [x] Add source-guard coverage proving first sign does not call
      `WARM_SESSION_MATERIAL_CLAIM` or any PRF-returning helper in the Ed25519
      restore path.
- [x] Add source-guard coverage proving the handle is one-use, short-TTL,
      exact-session scoped, and cleared after consume, expiry, exhaustion, or
      scope mismatch.
- [x] Add source guards proving warm-session unseal handles are never persisted,
      logged, serialized into route requests, or used as signing readiness.
- [x] Add source guards proving the optional handle path cannot call Ed25519 HSS
      reconstruction, Ed25519 HSS routes, or raw `xClientBaseB64u` helpers.
- [x] Add source guards proving Ed25519 restore files cannot call
      `claimWarmSessionPrfFirst()` or receive `prfFirstB64u`.
- [x] Browser evidence: passkey unlock with a restoreable sealed Ed25519 artifact
      installs the handle, first NEAR signing consumes exactly one restore
      authorization, and no second WebAuthn prompt appears before signing. This
      belongs with the final browser evidence pass, because it depends on the
      full app harness and Refactor 70 budget state. Evidence is pinned by
      `routerAb.serverBudgetEvidence.walletIframe.test.ts`: the cold-material
      Ed25519 browser test traces secure-confirm worker PUT/CLAIM commands,
      removes only the persisted material-handle hint while preserving the live
      near-signer authorization handle, asserts zero WebAuthn prompts between
      unlock and the first three Ed25519 signs, and verifies exactly one Rust
      worker-material restore before the first NEAR transaction.

## Phase 6: Optional Background Worker Restore

Default unlock behavior should stay fast. Background worker restore is an
optional follow-up for apps that want immediate signing readiness after unlock.
It must validate or restore a signer-core-owned material handle without HSS.
It may consume one credential-scoped unseal authorization use. It must not
consume server signature budget, reserve transaction budget, or call Router A/B
final signing routes. When no unseal authorization is available, it emits a
background restore failure and leaves unlock successful.

- [ ] Add an explicit public option only if product wants this behavior.
- [ ] Model the option as a narrow discriminated union, for example:

```ts
type UnlockSigningMaterialRestorePolicy =
  | { kind: 'lazy'; background?: never }
  | { kind: 'background'; background: true };
```

- [ ] Keep the default as `lazy`.
- [ ] Require an active credential-scoped unseal authorization handle for the
      `background` branch.
- [ ] Prove background restore never decrements server-authoritative signature
      budget.
- [ ] Emit background worker-restore events separately from unlock success.
- [ ] Ensure background restore failures do not flip a successful unlock into a
      failed unlock.
- [ ] Add a source guard proving background restore cannot call Ed25519 HSS
      reconstruction or HSS routes.

## Phase 7: Tests And Guards

- [x] Add a source guard proving unlock, registration, session bootstrap,
      signing-surface wiring, and daily signing cannot call deleted Ed25519
      material helpers.
- [x] Add a source guard proving `unlock()` and daily signing cannot call:
  - `prewarmThresholdEd25519ClientBaseFromCredential`
  - `ensureThresholdEd25519HssSigningMaterial`
  - `runThresholdEd25519HssCeremonyWithMaterialHandle`
  - Ed25519 HSS route clients

- [x] Add a source guard proving unlock postconditions do not require
      `ed25519WorkerMaterialHandle`.
- [x] Add unit tests/evidence for:
  - Ed25519 unlock with active budget and missing material handle.
  - Ed25519 unlock failure when Wallet Session auth is missing.
  - Ed25519 unlock failure when budget is expired or exhausted.
  - Registration persists an opaque worker-owned material restore artifact.
  - Registration persists durable material facts separately from warm-session
    activation facts.
  - First NEAR sign restores a pending material session without HSS.
  - First NEAR sign returns `material_unseal_authorization_required` before
    signing when unseal authorization is unavailable. - Passing focused evidence lives across
    `tests/unit/warmEd25519SigningSessionAuthorization.unit.test.ts`,
    `tests/unit/warmSessionEd25519Persistence.unit.test.ts`,
    `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`, and
    browser evidence in
    `tests/e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`. - `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts` is stale fixture
    debt in this worktree. It currently fails with
    `Router A/B Ed25519 restored worker material state did not become
signable` and should not be treated as release evidence until those
    fixtures are reconciled.
  - Worker handle reuse skips HSS.
  - Worker-owned material restore skips relay HSS after that restore path lands.
  - NEP-413 restores through the same helper as NEAR transactions.
  - NEP-461 delegate signing restores through the same helper as NEAR
    transactions.

- [x] Add a transaction-flow test proving `material_pending` reaches
      `persistStoredThresholdEd25519SessionMaterialHandle()` before Router A/B
      normal signing. - Evidence: `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`
      covers restore-before-normal-signing, lost worker-handle restore,
      Email OTP opaque unseal authorization, and repaired pending-material
      records resolving as signable before Router A/B signing.
- [x] Add a source guard proving daily signing code cannot call Ed25519 HSS
      reconstruction or HSS routes.
- [x] Add a focused source guard proving normal Ed25519 signing flows do not
      read or write raw `xClientBaseB64u`.
- [x] Add a source guard rejecting new TypeScript code that reads or writes raw
      `xClientBaseB64u` outside explicit HSS client boundaries and
      persistence/recovery stale-record rejection paths.
- [x] Add a source guard proving `near-signer.worker.ts` does not store
      `xClientBaseB64u` in a TypeScript map.
- [x] Add a focused source guard proving the NEAR signing material resolver does
      not read raw PRF.first material.
- [x] Add a source guard proving Ed25519 material restore and normal signing do
      not read raw PRF.first bytes in TypeScript outside the credential-confirm
      worker boundary.
- [x] Add a source guard proving core SDK, persistence, route-client,
      warm-session, and signing files do not construct secret-bearing
      material-authorization request objects with `prfFirstBytes` or
      `recoveryCodeSecret32`.
- [x] Add a source guard proving final generated worker command types do not
      expose `clientOutputMaskB64u`; any remaining occurrence must be isolated
      to transitional HSS output boundary decoding code.
- [x] Add a source guard proving no active Ed25519 restore path persists sealed
      PRF claims, sealed unseal-authorization refs, or recovery-code-derived
      seal bytes.
- [x] Add a source guard proving Ed25519 material error mapping uses
      `recovery_code`, not `email_otp`, for material seal/unseal secrets.
- [x] Add Rust/WASM tests for `StoreThresholdEd25519WorkerMaterialFromHssOutput`,
      `RestoreThresholdEd25519WorkerMaterial`, and
      `ValidateThresholdEd25519WorkerMaterial`. - Current coverage: `wasm/near_signer/src/threshold/worker_material.rs`
      covers store-from-base-share plus validate/presign, sealed artifact
      put/read/delete, and restore into the worker registry. - Store-from-HSS success coverage now runs with
      `hss-client-exports,hss-server-exports` and proves a real HSS output
      is opened with a Rust-owned mask handle, sealed, stored, and loaded
      into the worker material registry.
- [x] Add Rust/TypeScript parity tests for material binding digest, session
      binding digest, and sealed artifact AAD canonicalization.
- [x] Add Rust crypto tests for wrong AAD, wrong unseal secret, wrong material
      binding, corrupt ciphertext, wrong nonce length, and verifier mismatch.
- [x] Add SDK wrapper tests proving restore/read/delete material failures remain
      typed material result unions.
- [x] Add near-signer worker-wrapper tests proving `sealedWorkerMaterialRef`
      read failures map to `material_restore_required` or `material_corrupt`
      as specified.
- [x] Add worker tests proving credential-scoped unseal authorization handles
      are scoped to one `materialBindingDigest`, expire, decrement uses, and
      never expose secret bytes through TypeScript.
- [x] Add worker tests proving v1 credential authorization handles use
      `maxUses: 1`, default to a 60-second TTL, and reject a TTL above the
      5-minute cap unless an explicit typed server-authorized capability branch
      is introduced.
- [x] Add worker tests proving `seal` handles cannot restore material and
      `unseal` handles cannot create or replace sealed material.
- [x] Add sign-flow tests proving create-presign and sign-presign validate
      `Ed25519WorkerMaterialSessionBindingV1` before returning protocol
      messages.
- [x] Run the focused SDK web type check.
- [x] Run focused warm-session, runtime-postcondition, and NEAR signing tests.

Validated evidence:

- `tests/unit/warmEd25519SigningSessionAuthorization.unit.test.ts` covers
  material-pending unlock authorization and auth/budget rejection.
- `tests/unit/signingCapabilityStrictRecords.unit.test.ts` covers signable
  Ed25519 record rejection for missing worker material and stale raw material.
- `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts` covers strict
  Router A/B-ready state parsing and material-handle persistence cleanup.
- `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` guards daily signing
  against hidden Ed25519 HSS repair and raw client-base use in active final
  signing.
- `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` guards prepared material
  authorization surfaces, recovery-code-domain naming, the PRF-free NEAR
  signing material resolver, credential-boundary secret handling, the
  prepared-unseal restore boundary, and shared material-loader parity across
  NEAR transaction, NEP-413, and delegate signing.
- `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts` now guards
  the shared pending-material fail-closed path across NEAR transaction, NEP-413,
  and delegate signing.
- `tests/unit/thresholdEd25519.hssMaterialHandle.unit.test.ts` covers loaded
  worker-handle validation without PRF/HSS reconstruction and guards the
  material-ref builder boundary.
- `cargo test --manifest-path wasm/near_signer/Cargo.toml
threshold::worker_material -- --nocapture` covers sealed material storage,
  restore, validation, and seal/unseal authorization purpose rejection.
- `pnpm exec playwright test
tests/unit/thresholdEd25519.nearSignerWasm.unit.test.ts` covers SDK wrapper
  routing for store, restore, sealed storage, presign, digest, and credential
  material authorization installer calls.
- `pnpm --dir packages/sdk-web exec tsc --noEmit --pretty false` passed after
  making `sealAuthorization` required on store and prepared seal authorization
  required on material-handle HSS setup.
  The latest run is blocked by concurrent server-budget edits in
  `packages/sdk-server-ts` (`authReleaseReservedBudgetUseCountForIdentity`,
  `releaseRouterAbNormalSigningBudgetForIdentity`, and a missing
  `releaseReservedUseCountForIdentity` test fixture method), which are outside
  this Agent B slice.
- `pnpm exec playwright test tests/unit/refactor74LoginNoHss.guard.unit.test.ts
--reporter=line` passed after moving passkey seal authorization PRF extraction
  inside the credential-boundary helper and guarding `finally` zeroization.
- `pnpm --dir packages/sdk-web exec tsc --noEmit --pretty false` passed for the
  same passkey-boundary slice.
- `pnpm exec playwright test tests/unit/refactor74LoginNoHss.guard.unit.test.ts
--reporter=line` passed after adding the Email OTP opaque recovery-code unseal
  authorization branch to NEAR Ed25519 step-up restore.
- `pnpm --dir packages/sdk-web exec tsc --noEmit --pretty false` passed after
  wiring the same Email OTP direct-restore consumer path.
- `pnpm -C packages/sdk-web build` passed after durable sealed Ed25519 restore
  metadata was extended to include worker-material binding facts.
- `pnpm -C tests exec playwright test --reporter=line
unit/warmSessionEd25519Persistence.unit.test.ts
unit/routerAbEd25519.walletSessionState.unit.test.ts
unit/sealedSessionStore.unit.test.ts` passed after rebuilding the SDK dist.
  This covers warm-session material retention, strict runtime-validated
  Router A/B Ed25519 classification, Email OTP opaque restore authorization,
  and sealed-store boundary normalization.
- `pnpm exec playwright test tests/unit/stepUpAuthorization.builders.unit.test.ts
tests/unit/routerAbEd25519.walletSessionState.unit.test.ts --reporter=line`
  is currently blocked before test discovery by the shared test setup import
  `@/plugins` in `tests/setup/cross-origin-headers.ts`; the failure occurs before
  these test files execute.
- `pnpm exec playwright test tests/unit/refactor74LoginNoHss.guard.unit.test.ts
--reporter=line` now covers 15 Refactor 74 source guards, including the
  secret-bearing material authorization request boundary.

Open mask-transport dependency:

- Store command `clientOutputMaskB64u` deletion is complete. The remaining
  HSS output-mask cleanup should move
  `buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm()` onto the
  same byte-capable worker-local transport or Rust-owned mask-handle path. The
  current material HSS ceremony still uses the output mask for the staged
  evaluator artifact before store.

## Phase 8: Delete Legacy TypeScript Material Paths

Run this phase after Phase 4 has a working worker-owned restore path for NEAR
transactions, NEP-413, and delegate signing. The goal is to make the new
worker-owned model look like it was always the only implementation.

- [x] Delete `thresholdEd25519HssMaterialByHandle` and
      `StoredEd25519HssMaterial` from
      `packages/sdk-web/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`.
- [x] Delete the public `ThresholdSignerConfig.xClientBaseB64u` raw-material
      escape hatch.
- [x] Delete the direct
      `CreateThresholdEd25519RoleSeparatedNormalSigningClientShare` SDK wrapper,
      worker operation mapping, and HSS client-worker dispatch case that accepted
      caller-supplied `xClientBaseB64u`.
- [x] Delete TypeScript code that stores, validates, derives from, or passes
      raw `xClientBaseB64u` outside a persistence/request-boundary rejection or
      deletion path. - Source guard:
      `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` keeps remaining
      references classified as HSS setup/export, generated command typing,
      boundary rejection/deletion, or typecheck fixtures.
- [x] Delete raw `xClientBaseB64u` fields from active Ed25519 session/material
      records after the boundary parser rejects or prunes old records.
- [x] Rename remaining HSS-named normal-signing helpers to worker-material names
      after their behavior no longer invokes HSS. - `requireThresholdEd25519HssSigningMaterialHandle()` is now
      `requireThresholdEd25519WorkerMaterialHandle()` in
      `workerMaterialHandle.ts`; HSS derivation constants remain in
      `hssClientBase.ts`.
- [x] Delete deterministic TypeScript material-handle derivation such as
      `ed25519-hss-material:${thresholdSessionId}:...`.
- [x] Delete old `ed25519HssMaterialHandle` and
      `ed25519HssMaterialBindingDigest` active-path names after
      `materialHandle` and `materialBindingDigest` are wired through the
      worker-owned model.
- [x] Delete temporary fail-closed `material_restore_required` placeholders
      that were only needed before `RestoreThresholdEd25519WorkerMaterial`
      existed. - Remaining `material_restore_required` branches are the typed
      fail-closed behavior for missing sealed material, unavailable restore
      authorization, or worker-material validation failure before signing.
- [x] Delete the old direct PRF claim call paths from normal
      Ed25519 signing. Keep PRF/recovery-code secret handling only at the
      credential-boundary unseal authorization handle creation path.
- [x] Delete or convert tests, fixtures, mocks, and source guards that preserve
      obsolete raw-client-base cache behavior. Remaining raw-client-base tests
      assert boundary rejection or pruning.
- [x] Add final source guards proving active SDK TypeScript cannot read, write,
      log, compare, or route raw Ed25519 client MPC material.
- [x] Add final source guards proving normal Ed25519 unlock/signing cannot call
      Ed25519 HSS routes, reconstruction helpers, or HSS material-handle
      helpers.
- [x] Add focused tests proving existing-account stale raw-material records are
      pruned or rejected at the persistence boundary and do not revive legacy
      signing behavior.

Implementation note, June 20, 2026:

- Active `ThresholdEd25519SessionRecord` objects no longer carry
  `xClientBaseB64u`.
- `upsertStoredThresholdEd25519SessionRecord()` rejects raw-only Ed25519
  client-base input at the store boundary and drops raw client-base input when a
  real worker material handle or sealed worker material reference is present.
- Router A/B Ed25519 signing session parsing no longer exposes
  `raw_material_without_handle`; missing worker material is classified as
  `missing_material_handle` / pending material.

## Phase 9: Delete Defensive Legacy Fallbacks

This phase removes the remaining defensive cleanup patterns from earlier
wallet-session shapes. These branches were useful while the no-HSS model was
being introduced, but they now make the code harder to reason about and can hide
the exact source of truth for material readiness, budget authority, and restore
authorization.

Target principle: exact signing and unlock flows must use exact session/grant
facts, typed restore state, and server-authoritative budget state. Account-wide
or latest-record lookup may remain only in explicitly named account-scoped
discovery flows, never in exact login, exact warm-session install, or transaction
signing readiness.

### Context Preservation Policy

Do not commit commented-out legacy implementations. This repo is still in
development, and duplicate compatibility code makes the final lifecycle harder
to audit. Preserve the reason a fallback existed in this phase, focused tests,
and the commit message for each cleanup slice.

If a developer wants a temporary local checkpoint while replacing a fallback,
the workflow is:

1. Comment out the old block locally and add the new typed implementation in
   the same working tree.
2. Run the focused test or source guard for that slice.
3. Move any useful rationale into this plan or a short code comment near the new
   branch.
4. Delete the commented-out block before commit.

Committed code should contain only the new implementation plus a concise comment
when the reason is subtle.

### Fallback Smell Analysis

#### Passkey Ed25519 Pre-Planning Restore Best Effort

Location:
`packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`

Why it existed:

- The no-HSS restore path landed while warm-session auth planning still had to
  support auth-only records, material-pending records, and already-loaded worker
  handles.
- A soft restore before planning reduced extra passkey prompts when a prior
  unlock had already installed usable material authorization.
- During the transition, sealed material could be absent for old records, so the
  caller tolerated restore failure and let later material classification decide.

Keep it?

- Keep the optimization that tries to restore before choosing a step-up prompt.
- Delete the catch-and-continue shape. Auth planning should receive a typed
  result and switch exhaustively over every outcome.

Replacement plan:

- Introduce a `PrePlanningEd25519MaterialRestoreResult` union with branches:
  `restored`, `already_ready`, `missing_unseal_authorization`,
  `missing_sealed_material`, `worker_restore_failed`, and `not_applicable`.
- Replace `restorePasskeyEd25519SessionBeforePlanningBestEffort()` with a helper
  that never swallows errors into an implicit continue.
- Make the planner switch on that union. Only `restored`, `already_ready`, and
  `not_applicable` may continue without fresh credential authorization.
- Add tests where pending material restore fails and the planner chooses the
  typed reauth/restore branch instead of warm-session auth.

#### Account-Scoped Latest Ed25519 Restore

Location:
`packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`

Why it existed:

- Early warm-session startup often knew the wallet/account before it knew the
  exact signing grant and threshold session.
- Account-scoped lookup helped repair or discover the newest usable Ed25519
  material after reloads and during migration from raw material records.
- It also helped diagnostics show whether any durable Ed25519 artifact existed.

Keep it?

- Keep only for account-scoped discovery, repair, and diagnostics.
- Delete every exact unlock/signing-lane dependency on latest-record lookup.

Replacement plan:

- Rename any remaining account-scoped helper so the name includes
  `AccountScoped`, `Discovery`, `Repair`, or `Diagnostics`.
- Add exact restore helpers that require `walletId`, `authMethod`,
  `signingGrantId`, `thresholdSessionId`, and material binding facts.
- Add a source guard proving exact login, exact warm-session material install,
  NEAR transaction signing, NEP-413 signing, and delegate signing cannot call
  account-scoped/latest restore helpers.

#### Negative Missing-Restore Cache

Location:
`packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`

Why it existed:

- Repeated restore attempts could hammer IndexedDB and worker state after a
  sealed record was known missing.
- During transition, missing sealed material was common for old accounts, so the
  cache avoided repeated expensive miss paths.

Keep it?

- Prefer deletion for exact restore paths.
- If retained for account-scoped discovery, it must be short-lived and
  invalidated by sealed-store writes/deletes for the same scope.

Replacement plan:

- First try deleting the cache for exact restore and rely on cheap exact
  IndexedDB lookup plus typed missing result.
- If performance requires a cache, replace it with a scoped TTL cache keyed by
  exact `walletId`, `authMethod`, `curve`, `signingGrantId`,
  `thresholdSessionId`, `materialBindingDigest`, and reason.
- Wire sealed-session write/delete paths to invalidate matching cache entries.
- Add a stale-negative-cache test that misses, writes sealed material, and then
  proves exact restore sees the new artifact.

#### Email OTP ECDSA Field-By-Field Restore Fallback

Location:
`packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`

Why it existed:

- Email OTP recovery had to bridge records written at different lifecycle points:
  current ECDSA readiness records, sealed session records, and recovery records.
- Some records carried identity fields that others did not, so fallback made the
  restore path permissive during migration.

Keep it?

- Delete field-level mixing for identity and restore facts.
- Keep separate source branches for current-record restore and sealed-record
  restore.

Replacement plan:

- Define `EmailOtpEcdsaRestoreSource` as a discriminated union:
  `current_record_restore` and `sealed_record_restore`.
- Build each branch through a parser that requires the full envelope for that
  source: wallet, chain target, key handle, relayer key, participants, grant,
  session, and recovery authorization facts.
- Reject mixed current/sealed identity fields.
- Add tests proving mixed fields fail and each complete source branch restores.

#### Budget Compatibility Fallbacks

Location:
`packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`

Why it existed:

- Refactor 70 moved budget authority to the server while older records still
  had persisted remaining-use and reservation hints.
- Parsers needed to tolerate old field names while route and store responses
  were converging.

Keep it?

- Keep compatibility fallback only inside boundary parsers that normalize raw
  server/store shapes.
- Signing admission should receive a normalized trusted budget status with
  required authority fields.

Replacement plan:

- Introduce or reuse a parser that returns a precise internal
  `TrustedSigningBudgetStatus`.
- Make active/admitted branches require normalized `availableUses`,
  `expiresAtMs`, reservation identity, and exhaustion facts.
- Route signing admission through `availableUsesForBudgetAdmission(status)`.
- Add tests proving malformed active status and persisted policy hints cannot
  admit signing.

#### First-Candidate Selection Fallbacks

Locations:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`

Why they existed:

- Candidate lists were already filtered in nearby code, so returning
  `candidates[0] || null` was a compact way to choose the only expected match.
- Some UI/status aggregation needed a best available display value when exact
  active status was missing.

Keep it?

- Keep only after exact filtering is represented in the type or helper name.
- Delete first-candidate selection from authority-bearing lifecycle code.

Replacement plan:

- Replace loose candidate arrays with branch-specific selection results:
  `exact_match`, `ambiguous`, `not_found`, and `display_only_fallback`.
- For display-only aggregation, name the function or branch `displayOnly`.
- For authority paths, require one exact match and fail closed on ambiguity.
- Add source guards for `candidates[0] || null` in signing/session lifecycle
  directories.

#### PRF And Recovery-Code Cache Reachability

Location:
`packages/sdk-web/src/core/signingEngine/session/passkey/prfCache.ts`

Why it existed:

- The SDK needed to avoid repeated credential prompts across setup/export and
  restore operations while passkey PRF handling was still in TypeScript-facing
  warm-session code.
- PRF cache helpers were an intermediate bridge before Ed25519 restore received
  opaque credential-boundary unseal handles.

Keep it?

- Keep only for explicitly named credential-boundary setup/export paths.
- Delete reachability from normal Ed25519 unlock/signing restore.

Replacement plan:

- Rename remaining helpers so names include credential boundary and purpose,
  such as `cacheEcdsaHssSetupPrfHandle`.
- Add a guard proving normal Ed25519 restore files cannot call PRF-returning
  helpers or receive `prfFirstB64u`.
- Replace remaining Ed25519 restore usage with opaque one-use unseal
  authorization handles.

#### Email OTP Companion Session Best Effort

Location:
`packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts`

Why it existed:

- Email OTP flows could create or attach companion Ed25519 session metadata
  opportunistically while the main flow remained focused on account control.
- A soft helper avoided failing the entire Email OTP flow when the companion
  session attachment was not required for the immediate operation.

Keep it?

- Keep optional companion attachment only when the caller explicitly models it
  as optional.
- Delete silent best-effort behavior when a later direct restore depends on that
  companion metadata.

Replacement plan:

- Return a typed `EmailOtpCompanionSessionAttachResult` with branches:
  `attached`, `already_attached`, `not_required`, `missing_required_material`,
  and `failed`.
- Make callers decide whether `missing_required_material` or `failed` is fatal
  for their operation.
- Add diagnostics that report the branch without turning it into restore
  readiness.
- Add tests for Email OTP direct restore requiring opaque unseal authorization
  and complete companion metadata.

### Detailed Target Specs

#### Pre-Planning Ed25519 Restore Result

Replace implicit `try/catch` restore planning with a narrow union. The helper
may still attempt an optimization before the prompt planner runs, but the result
must be explicit.

```ts
type PrePlanningEd25519MaterialRestoreResult =
  | {
      kind: 'already_ready';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'restored';
      capability: NearEd25519Capability;
      restored: number;
    }
  | {
      kind: 'not_applicable';
      reason:
        | 'auth_method_not_passkey'
        | 'record_not_restore_available'
        | 'operation_does_not_require_ed25519_material';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'missing_unseal_authorization';
      code:
        | 'not_found'
        | 'expired'
        | 'exhausted'
        | 'scope_mismatch'
        | 'material_unseal_authorization_required';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'missing_sealed_material';
      code:
        | 'no_durable_restore_records'
        | 'durable_restore_missing_worker_material'
        | 'material_restore_required';
      capability: NearEd25519Capability;
    }
  | {
      kind: 'worker_restore_failed';
      code:
        | 'restore_command_failed'
        | 'worker_validation_failed'
        | 'capability_refresh_failed'
        | 'unexpected_restore_error';
      capability: NearEd25519Capability;
      message: string;
    };
```

Planner behavior:

- `already_ready`, `restored`, and `not_applicable` may continue without a fresh
  credential prompt.
- `missing_unseal_authorization` must choose the passkey material-restore
  prompt branch when the record is otherwise restoreable.
- `missing_sealed_material` must fail closed as material restore required.
- `worker_restore_failed` must fail closed with a typed restore failure. It must
  not silently continue with warm-session auth.

Error mapping:

- `material_unseal_authorization_required`, warm-session unseal claim
  `not_found`, `expired`, `exhausted`, or `scope_mismatch` maps to
  `missing_unseal_authorization`.
- `material_restore_required`, `no_durable_restore_records`, and
  `durable_restore_missing_worker_material` maps to `missing_sealed_material`.
- Worker command failure, failed material validation, thrown IndexedDB read
  failure after restore, and unexpected exceptions map to `worker_restore_failed`.
- A current `runtime_validated` capability maps to `already_ready` before any
  restore attempt.

`readRefreshedEd25519CapabilityOrCurrent()` must also be replaced. A failed
post-restore capability read is `worker_restore_failed` with
`code: 'capability_refresh_failed'`; it must not fall back to stale current
state.

#### Exact Restore Versus Account-Scoped Restore Allowlist

Account-scoped/latest Ed25519 restore is allowed only for these purposes:

- account-scoped startup discovery that does not mark exact signing readiness;
- explicit user-triggered repair;
- diagnostics that report available records without mutating active signing
  state;
- tests proving exact restore cannot call account-scoped helpers.

Allowed helper names must include one of:

- `AccountScoped`
- `Discovery`
- `Repair`
- `Diagnostics`

Exact unlock, exact warm-session material install, NEAR transaction signing,
NEP-413 signing, and delegate signing must call exact helpers that require:

- `walletId`
- `authMethod`
- `curve`
- `signingGrantId`
- `thresholdSessionId`
- `materialBindingDigest` for Ed25519 material restore
- ECDSA `chainTarget` for ECDSA restore

`hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial()` must either be
renamed to an allowed account-scoped name or deleted after exact callers move
off it.

#### Negative Restore Cache Spec

Preferred implementation: delete the `knownMissing` cache for exact restore.
Exact restore should do one exact sealed-record lookup and return a typed
missing result. Keep the successful-restore cache only when it prevents repeated
work for the same already-restored durable record.

If profiling later proves a missing cache is needed, it must be account-scoped
only and use:

```ts
type KnownMissingRestoreCacheEntry = {
  kind: 'known_missing_restore_v1';
  walletId: string;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  signingGrantId: string;
  thresholdSessionId: string;
  materialBindingDigest?: string;
  ecdsaChainTargetKey?: string;
  reason: string;
  expiresAtMs: number;
};
```

Rules:

- TTL must be short, with a default of 10 seconds and a hard cap of 60 seconds.
- Exact signing restore must not consult this cache.
- Sealed-session write/delete must invalidate entries with matching wallet,
  auth method, curve, signing grant, threshold session, and material binding or
  ECDSA chain target.
- The cache API must expose `invalidateForSealedSessionWrite(record)` and
  `invalidateForSealedSessionDelete(scope)` if the cache remains.

Store/write call sites to account for:

- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  `registerSigningSession`, `readExactSealedSession`,
  `deleteExactSealedSession`, and replacement writes.
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
  sealed-session writes after setup, refresh, and persisted-session refresh.
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedSessionRegistry.ts`
  Email OTP sealed-session writes.

#### Email OTP ECDSA Restore Source Union

The ECDSA restore path always needs the sealed record for the sealed secret,
remaining uses, expiry, and seal transport. The identity envelope must come from
one validated source branch.

```ts
type EmailOtpEcdsaRestoreSource =
  | {
      kind: 'sealed_record_restore';
      sealedRecord: CurrentEcdsaSealedSessionRecord;
      ecdsaRecord?: never;
      walletSessionJwt: string;
      thresholdSessionId: string;
      signingGrantId: string;
      relayerUrl: string;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      relayerKeyId: string;
      participantIds: readonly number[];
      sessionKind: 'jwt';
      runtimePolicyScope?: string;
    }
  | {
      kind: 'current_record_restore';
      sealedRecord: CurrentEcdsaSealedSessionRecord;
      ecdsaRecord: ThresholdEcdsaSessionRecord;
      walletSessionJwt: string;
      thresholdSessionId: string;
      signingGrantId: string;
      relayerUrl: string;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      relayerKeyId: string;
      participantIds: readonly number[];
      sessionKind: 'jwt';
      runtimePolicyScope?: string;
    };
```

Branch rules:

- `sealed_record_restore` reads the full identity envelope from
  `sealedRecord`. A companion `ecdsaRecord`, when present, may be used only to
  verify exact equality. It must not supply missing fields.
- `current_record_restore` reads the full identity envelope from `ecdsaRecord`
  and verifies exact equality with the sealed record for wallet, curve, auth
  method, signing grant, threshold session, chain target, signing root, and
  runtime policy scope.
- `sealedRecord` must provide `sealedSecretB64u`, `remainingUses`,
  `expiresAtMs`, signing-session seal key version, and Shamir prime. Config
  fallback is allowed only inside a persistence boundary parser that upgrades or
  rejects old records before this restore function runs.
- Wallet Session JWT must come from the same selected source branch. A current
  branch with missing current JWT must fail branch construction rather than
  borrowing JWT from the sealed record.
- Mixed branch construction is invalid at the type level. Use `never` fields and
  `@ts-expect-error` fixtures for mixed objects.

#### Trusted Budget Admission Type

Reuse the existing budget model instead of creating a parallel one. The internal
admission type should be a required-field refinement of the existing
`SigningSessionStatus` active branch:

```ts
type TrustedActiveSigningBudgetStatus = SigningSessionStatus & {
  status: 'active';
  remainingUses: number;
  committedRemainingUses: number;
  inFlightReservedUses: number;
  availableUses: number;
  expiresAtMs: number;
  projectionVersion: string;
};
```

Budget admission must switch over every status branch:

- `active`: require `TrustedActiveSigningBudgetStatus` and call
  `availableUsesForBudgetAdmission(status)`.
- `exhausted`: reject with budget exhausted.
- `expired`: reject with budget expired.
- `unavailable`: reject with budget unavailable.
- `budget_unknown`: reject with budget unknown.
- `not_found`: reject with budget missing.

Compatibility fallback such as `record.availableUses ?? record.remainingUses`
may exist only in the boundary parser that normalizes raw status records. Core
signing admission must not read persisted record policy hints or optional budget
fields.

UI-only budget display must use separately named helpers such as
`selectSigningSessionStatusForDisplay()` and must not feed signing admission.

#### Candidate Selection Classification

Every first-candidate fallback must be classified before implementation:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
  `selectReconnectWalletSessionJwt()` is authority-bearing because it selects a
  JWT for reconnect. Replace `candidates[0] || null` with
  `exact_match`, `ambiguous`, and `not_found`. If no JWT matches the target
  ECDSA identity, reconnect must fail closed.
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
  `selectSigningSessionStatusForUi()` is display-only. Rename it to
  `selectSigningSessionStatusForDisplay()` and switch over `active`,
  `exhausted`, `expired`, `unavailable`, `budget_unknown`, and `not_found`.
  It may return a display fallback, and that result must not be passed into
  signing admission.
- `snapshotLaneToSigningSessionStatus()` may use `policyHint` only for display.
  Rename or split the helper so any status built from `policyHint` cannot be
  consumed as trusted budget status.

#### Commented Legacy Guard

Source guards must reject committed commented-out legacy code. Add guard
patterns for:

```text
restorePasskeyEd25519SessionBeforePlanningBestEffort
hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial
knownMissingCacheKey
claimWarmSessionPrfFirst
WARM_SESSION_MATERIAL_CLAIM
ed25519-hss-material:
raw_material_without_handle
TODO remove legacy
LEGACY
old path
fallback path
```

Allowed hits are active code that is explicitly classified by Phase 9, tests
that assert rejection, or plan text. Commented-out implementation blocks are
not allowed in committed source.

#### Implementation Order

Implement Phase 9 in this order:

1. Add source guards for the existing smell inventory so regressions are visible
   before behavior changes.
2. Replace pre-planning restore best-effort with the typed result union and
   remove `readRefreshedEd25519CapabilityOrCurrent()` catch-and-current
   behavior.
3. Rename or delete account-scoped/latest Ed25519 restore usage from exact
   unlock/signing code, then add the exact-call source guard.
4. Delete `knownMissing` from exact restore. Add stale-miss coverage.
5. Replace Email OTP ECDSA field-level fallback with
   `EmailOtpEcdsaRestoreSource`.
6. Tighten budget admission to consume trusted active budget status only.
7. Classify and replace first-candidate fallbacks.
8. Tighten PRF/recovery-code cache reachability and Email OTP companion-session
   attachment results.
9. Run focused unit/typecheck/source-guard tests.
10. Rerun no-HSS browser evidence after the cleanup slices land.

### Test-First Guard Plan

The first committed Phase 9 slice should add passing inventory guards before
behavior changes. These guards must freeze the known fallback sites and prevent
new fallback sites from appearing while the refactor is in progress.

Add a focused guard file:

```text
tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts
```

The guard file should follow the existing source-guard style from
`tests/unit/refactor74LoginNoHss.guard.unit.test.ts`: read source files from the
repo, inspect exact source ranges, and report all offenders in one failure.

Initial guard behavior:

- Maintain a `knownPhase9FallbackInventory` array with:
  - marker;
  - file path;
  - owner phase item;
  - allowed reason;
  - expected removal or rename step.
- Fail on any matching marker outside the inventory.
- Fail if an inventoried marker disappears without its inventory entry being
  updated. This forces the implementer to mark off the cleanup deliberately.
- Exclude `docs/refactor-74-login-no-hss.md` and the guard file itself from
  marker scans.
- Exclude `.typecheck.ts` only when scanning for runtime control-flow markers;
  include `.typecheck.ts` when checking type-level guarantees.

Known initial inventory:

```text
packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts
  restorePasskeyEd25519SessionBeforePlanningBestEffort
  readRefreshedEd25519CapabilityOrCurrent

packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts
  hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial

packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts
  knownMissingCacheKey
  rememberKnownMissing
  hasKnownMissing

packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts
  || sealedRecord
  ecdsaRecord?.
  args.configs.signing.sessionSeal

packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts
  selectReconnectWalletSessionJwt
  candidates[0] || null

packages/sdk-web/src/SeamsWeb/operations/auth/login.ts
  selectSigningSessionStatusForUi
  snapshotLaneToSigningSessionStatus
  ?? lane.policyHint

packages/sdk-web/src/core/signingEngine/session/passkey/prfCache.ts
  cacheSigningSessionPrfFirstBestEffort

packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts
  attachEd25519SessionToEmailOtpSigningSessionSealBestEffort
```

The guard should also reject committed commented-out implementation blocks by
scanning active source for commented lines containing Phase 9 markers:

```text
// restorePasskeyEd25519SessionBeforePlanningBestEffort
// readRefreshedEd25519CapabilityOrCurrent
// hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial
// knownMissingCacheKey
// candidates[0] || null
// claimWarmSessionPrfFirst
// WARM_SESSION_MATERIAL_CLAIM
// TODO remove legacy
// LEGACY
```

The allowed transition is:

1. Inventory guard lands and passes with current known offenders.
2. Each implementation slice writes target behavior/type tests locally and
   observes the expected failure.
3. The same slice implements the fix and updates the inventory guard by removing
   or renaming that offender.
4. The slice is committed only after source guards, unit tests, typecheck
   fixtures, and targeted runtime tests pass.

Do not commit failing target tests. Target tests should be introduced at the
start of the relevant implementation slice and committed with the fix.

### Required Test Changes Before Each Cleanup Slice

#### Pre-Planning Restore Tests

Target file:

```text
tests/unit/nearSigning.sessionSelection.unit.test.ts
```

Add tests before replacing the helper:

- pending passkey Ed25519 material with an expired or missing warm-session
  unseal handle produces a passkey material-restore reauth plan, not a
  warm-session plan;
- restore succeeds but refreshed capability read throws, producing
  `worker_restore_failed` instead of reusing stale current capability;
- current runtime-validated capability maps to `already_ready` and does not
  attempt restore;
- non-passkey auth method maps to `not_applicable`.

If current public helpers do not expose enough detail to assert the typed
result, extract a small pure planner helper from
`signingSessionAuthMode.ts`. The helper must be exported from the internal
module only if tests need it; it must not become public SDK API.

#### Account-Scoped Restore Guard Tests

Target file:

```text
tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts
```

Add source guards before renaming/deleting account-scoped restore:

- exact NEAR signing files must not import or call helpers with
  `Latest`, `AccountScoped`, `Discovery`, `Repair`, or `Diagnostics` in their
  Ed25519 material readiness path;
- exact login warm-up code must call an exact helper that takes
  `signingGrantId`, `thresholdSessionId`, and Ed25519 material binding facts;
- any allowed account-scoped helper must include one of the allowed names and
  must not call `persistStoredThresholdEd25519SessionMaterialHandle()`.

#### Negative Cache Tests

Existing test debt:

```text
tests/unit/signingSessionRestoreCoordinator.unit.test.ts
  "caches exact-purpose durable-record absence"
```

That test encodes the legacy behavior. Delete or rewrite it during the
negative-cache cleanup slice. Do not preserve tests that require exact restore
to cache missing durable records.

Replacement tests:

- exact restore calls the exact sealed-session lookup again after a miss;
- exact restore sees a sealed material record written after an earlier miss;
- successful restore caching, if retained, is keyed by durable record identity
  and cannot suppress a newer record with a different `updatedAtMs`,
  `signingGrantId`, `thresholdSessionId`, or material binding.

#### Email OTP ECDSA Source Tests

Target files:

```text
tests/unit/sealedRecovery.methodAdapters.unit.test.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.typecheck.ts
```

Add behavior tests:

- sealed-source restore succeeds only when the sealed record contains the full
  ECDSA identity envelope and Wallet Session JWT;
- current-record restore succeeds only when the current record contains the full
  ECDSA identity envelope and exactly matches the sealed record;
- current-record restore with missing JWT fails instead of borrowing JWT from
  the sealed record;
- mixed current/sealed `chainTarget`, `keyHandle`, `relayerKeyId`,
  `participantIds`, `thresholdSessionId`, `signingGrantId`, signing root, or
  runtime policy scope fails before worker restore;
- config fallback for signing-session seal key version or Shamir prime is
  rejected in core restore and accepted only by the boundary parser that
  normalizes old sealed records.

Add type fixtures:

- mixed `EmailOtpEcdsaRestoreSource` branches reject `ecdsaRecord` on
  `sealed_record_restore`;
- `current_record_restore` requires `ecdsaRecord`;
- both branches require `walletSessionJwt`, `chainTarget`, `keyHandle`,
  `relayerKeyId`, and `participantIds`;
- branch-specific objects use `never` fields to reject fallback bags.

#### Trusted Budget Admission Tests

Target files:

```text
tests/unit/walletSessionReadiness.gate.unit.test.ts
tests/unit/walletSessionBudgetReservation.store.unit.test.ts
packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts
```

Add behavior tests:

- malformed `active` status missing `availableUses`, `expiresAtMs`, or
  `projectionVersion` is rejected before signing admission;
- `active` status with `availableUses < remainingUses` admits only
  `availableUses`;
- `unavailable`, `budget_unknown`, `not_found`, `expired`, and `exhausted`
  branches all reject through explicit switch cases;
- UI display status built from `policyHint` cannot be passed to budget
  admission.

Add type fixtures:

- `TrustedActiveSigningBudgetStatus` requires every active authority field;
- optional `remainingUses`/`expiresAtMs` public status cannot satisfy trusted
  admission without boundary parsing;
- display-only status types are not assignable to trusted admission input.

#### Candidate Selection Tests

Target files:

```text
tests/unit/evmFamilyEcdsaIdentity.unit.test.ts
tests/unit/nearSigning.sessionSelection.unit.test.ts
```

Add behavior tests:

- `selectReconnectWalletSessionJwt()` returns exact match only;
- no matching JWT returns `not_found` or throws a typed reconnect identity error;
- multiple matching JWTs with conflicting identity metadata returns
  `ambiguous`;
- display-only signing status selection sorts and returns a display fallback
  without exposing a trusted budget status.

#### PRF Cache And Companion Session Tests

Target files:

```text
tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts
tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts
packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.typecheck.ts
```

Add guards/tests:

- normal Ed25519 signing restore files cannot import
  `cacheSigningSessionPrfFirstBestEffort` or any PRF-returning helper;
- remaining PRF cache helpers are named for credential-boundary setup/export;
- `attachEd25519SessionToEmailOtpSigningSessionSealBestEffort()` is replaced by
  a typed attachment result;
- callers switch over `attached`, `already_attached`, `not_required`,
  `missing_required_material`, and `failed`;
- direct Email OTP restore cannot treat companion attachment diagnostics as
  material readiness.

### Phase 9 Validation Matrix

Run these checks for each cleanup slice:

```bash
pnpm -C tests exec playwright test --reporter=line \
  unit/refactor74LegacyFallbacks.guard.unit.test.ts

pnpm -C tests exec playwright test --reporter=line \
  unit/refactor74LoginNoHss.guard.unit.test.ts

pnpm -C tests exec playwright test --reporter=line \
  unit/nearSigning.sessionSelection.unit.test.ts \
  unit/signingSessionRestoreCoordinator.unit.test.ts \
  unit/sealedRecovery.methodAdapters.unit.test.ts \
  unit/emailOtpWalletSessionCoordinator.unit.test.ts \
  unit/walletSessionReadiness.gate.unit.test.ts \
  unit/walletSessionBudgetReservation.store.unit.test.ts

pnpm -C packages/sdk-web exec tsc --noEmit --pretty false
```

After all Phase 9 cleanup slices land, rerun the browser evidence:

```bash
RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line \
  e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts
```

Evidence: reran on 2026-06-22 after Phase 9 compliance fixes; both browser
evidence tests passed.

### Phase 9 No-Regression Gates

The cleanup is complete only if these existing Refactor 74 guarantees still
hold:

- Passkey wallet unlock succeeds without Ed25519 HSS.
- A failed wallet unlock does not commit an active logged-in SDK state.
- After successful passkey unlock with a restoreable sealed Ed25519 artifact,
  the first NEAR transaction does not show a second WebAuthn prompt when the
  unlock-installed unseal handle is still live.
- A single NEAR transaction request shows one transaction confirmer modal.
- First cold Ed25519 signing restores through exactly one
  `RestoreThresholdEd25519WorkerMaterial` command before Router A/B signing.
- NEAR transaction, NEP-413, and delegate signing make zero Ed25519 HSS route
  calls.
- Worker-material restore does not decrement server-authoritative signature
  budget. Budget reservation/decrement starts only after material readiness is
  ready for signing.
- Shared signing-grant budget exhaustion still triggers step-up after the
  server-authoritative budget is exhausted.
- ECDSA Tempo/EVM signing still uses its ECDSA/HSS setup/export boundaries and
  is not affected by Ed25519 PRF-cache cleanup.

If a Phase 9 slice changes any of these behaviors, stop and fix the regression
before continuing to the next cleanup item.

### Cleanup Targets

- [x] Replace
      `restorePasskeyEd25519SessionBeforePlanningBestEffort()` in
      `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
      with a typed restore result. The planner must switch exhaustively over:
      `restored`, `already_ready`, `missing_unseal_authorization`,
      `missing_sealed_material`, `worker_restore_failed`, and `not_applicable`.
      The planner may continue without a prompt only for `restored`,
      `already_ready`, or `not_applicable`.
- [x] Replace `readRefreshedEd25519CapabilityOrCurrent()` with a typed refreshed
      capability read result. Read failures after restore must become
      `worker_restore_failed` and must not silently reuse stale capability state.
- [x] Ban account-scoped/latest Ed25519 durable restore helpers from exact
      login/signing-lane restore. `hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial()`
      may remain only for account-scoped discovery, repair, or diagnostics in
      `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`.
- [x] Rename every allowed account-scoped/latest helper to include
      `AccountScoped`, `Discovery`, `Repair`, or `Diagnostics`.
- [x] Add a source guard proving exact login, exact warm-session material
      install, NEAR transaction signing, NEP-413 signing, and delegate signing
      do not call account-scoped/latest Ed25519 restore helpers.
- [x] Remove or strictly scope the `knownMissing` negative restore cache in
      `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`.
      If the cache remains, it must have a short TTL, include exact
      `walletId`, `authMethod`, `curve`, `signingGrantId`,
      `thresholdSessionId`, and material binding facts, and be invalidated on
      every sealed-session write/delete for that scope.
- [x] Replace field-by-field Email OTP ECDSA restore fallback in
      `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`
      with a discriminated source:
      `current_record_restore` or `sealed_record_restore`. Each branch must
      validate the complete identity envelope before restoring.
- [x] Remove config fallback from core Email OTP ECDSA restore. Signing-session
      seal key version and Shamir prime fallback may exist only in the
      persistence boundary parser that normalizes or rejects old sealed records.
- [x] Audit `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
      and keep compatibility fallback only inside the boundary parser that
      normalizes server budget responses. Signing admission must consume a
      trusted normalized budget status and use server-authoritative
      `availableUses`, expiry, reservation, and exhaustion fields.
- [x] Reuse the existing budget model with a required-field
      `TrustedActiveSigningBudgetStatus` refinement. Do not create a parallel
      budget authority type.
- [x] Replace `candidates[0] || null` and similar first-candidate fallbacks in
      signing/session lifecycle code with explicit typed selection. If a helper
      intentionally returns the first already exact-filtered candidate, rename
      the helper or local variable so the exact filtering is visible at the call
      site.
- [x] Split authority-bearing candidate selection from display-only candidate
      selection. `selectReconnectWalletSessionJwt()` must fail closed on no
      exact JWT match; UI status selection must be renamed display-only and must
      not feed signing admission.
- [x] Keep PRF and recovery-code cache helpers only inside credential-boundary
      setup/export paths. `cacheSigningSessionPrfFirstBestEffort()` and related
      helpers must not be reachable from normal Ed25519 unlock/signing material
      restore.
- [x] Make Email OTP companion-session attachment typed and observable. If
      `attachEd25519SessionToEmailOtpSigningSessionSealBestEffort()` fails,
      callers must receive a typed result or explicit diagnostics that cannot be
      mistaken for a valid Ed25519 restore state.

### Deletion Rules

- Delete catch-and-continue restore branches in auth/material readiness code.
  Recoverable failures must return a `Result`-style discriminated union.
- Delete field-by-field record mixing for identity, restore, budget, material,
  and session facts. Use one validated source branch at a time.
- Delete account-scoped or latest-record restore from exact-session code paths.
- Delete negative-cache behavior that can outlive a sealed-session write for the
  same wallet/session/material scope.
- Keep compatibility parsing only at persistence and request boundaries. Core
  signing, auth planning, material restore, and budget admission must accept
  normalized internal types.

### Source Guard Inventory

Add or update guards that search active SDK code for these patterns:

```text
restorePasskeyEd25519SessionBeforePlanningBestEffort
readRefreshedEd25519CapabilityOrCurrent
hydrateLatestEd25519SessionFromDurableSealedWorkerMaterial
knownMissingCacheKey
candidates[0] || null
|| sealedRecord
?? record.
?? lane.policyHint
cacheSigningSessionPrfFirstBestEffort
attachEd25519SessionToEmailOtpSigningSessionSealBestEffort
selectReconnectWalletSessionJwt
selectSigningSessionStatusForUi
snapshotLaneToSigningSessionStatus
TODO remove legacy
LEGACY
old path
fallback path
```

Allowed hits must be classified as one of:

- boundary parser compatibility
- account-scoped discovery/repair/diagnostics
- explicit credential-boundary setup/export
- tests proving rejection of legacy behavior
- obsolete code scheduled for deletion in this phase

### Tests

- Add a focused NEAR auth-planning test where Ed25519 material is pending and
  pre-planning restore fails. The test must prove the planner chooses a typed
  reauth/restore branch instead of silently continuing with warm-session auth.
- Add a focused NEAR auth-planning test where post-restore capability refresh
  throws. The test must prove stale current capability state is not reused.
- Add a stale-negative-cache test: write sealed material after an earlier
  missing lookup, then prove exact restore sees the newly written material.
- Add an Email OTP ECDSA restore test proving mixed current/sealed identity
  fields are rejected and each valid source branch restores only with its own
  complete envelope.
- Add a budget admission test proving malformed or partial active status cannot
  fall back to persisted record policy hints for signing admission.
- Add reconnect JWT selection tests proving no exact identity match returns
  `not_found` or fails closed rather than returning the first candidate.
- Add display-status tests proving UI fallback statuses are display-only and do
  not reach budget admission.
- Add type fixtures for the new discriminated restore and source-selection
  unions. Invalid mixed branches must use `@ts-expect-error`.

### Done Criteria

- Exact wallet unlock, exact warm-session install, and normal signing material
  readiness contain no account-scoped/latest restore fallback.
- Auth/material planning uses exhaustive `switch` statements over typed restore
  outcomes.
- No material, identity, budget, or restore authority is assembled by mixing
  fields from multiple persisted records.
- Negative restore caches cannot hide a sealed material record written after a
  previous miss.
- Authority-bearing candidate selection fails closed on ambiguity or no exact
  match. Display-only fallbacks are named and cannot feed signing admission.
- Core Email OTP ECDSA restore receives complete normalized source branches; it
  does not borrow missing identity or seal transport fields from config or a
  different record.
- Commented-out legacy implementation blocks are absent from committed source.
- Source guards classify or delete every remaining defensive fallback marker.
- Existing no-HSS browser evidence still passes after cleanup.

## Validation Commands

Use the cheapest checks that cover this behavior:

```bash
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test \
  ./unit/runtimePostconditions.unit.test.ts \
  ./unit/warmSessionReadModel.unit.test.ts \
  ./unit/warmSessionStore.transitions.unit.test.ts \
  --reporter=line
```

Add or replace test targets as the implementation creates focused coverage.

Release gate: final browser evidence is required in addition to this spec.
After Refactor 70 lands, run the combined local/browser harness that proves
server-authoritative budget exhaustion UX, no-HSS unlock, lazy worker-material
restore, NEAR transaction signing, NEP-413 signing, and delegate signing all
work together. The Refactor 74 spec and source guards do not replace that
evidence harness.

Implementation note, June 20, 2026:

- Refactor 70 has landed, and the combined browser evidence now passes locally.
- The browser harness reads server-authoritative budget state for the shared
  wallet signing grant instead of relying on aggregate UI session selection,
  because exhausted Ed25519 lanes can be hidden by still-active ECDSA lanes.
- Wallet-iframe evidence reads the durable sealed Ed25519 session artifact from
  the wallet origin and uses the relayer status route as the budget authority.
  Diagnostic `ed25519State` reports a persisted material handle as
  `material_handle_hint`; only worker validation can prove runtime readiness.
- The lazy-restore browser path forces a cold Ed25519 material setup before the
  first sign by removing the durable worker-material handle hint, resetting the
  near-signer worker transport, and clearing runtime-validation state while
  preserving `sealedWorkerMaterialRef`.
- The lazy-restore browser path asserts setup is `material_pending`, the first
  NEAR transaction runs exactly one `RestoreThresholdEd25519WorkerMaterial`
  command, NEAR/NEP-413/delegate signing make zero Ed25519 HSS route calls, and
  the first three Ed25519 signs share the same server-authoritative budget until
  exhaustion.
- Cold material restore requires one passkey/WebAuthn prompt on the first sign
  to authorize unsealing. After that restore, NEAR transaction, NEP-413, and
  delegate signing proceed without another prompt before budget exhaustion.

## Refactor 74 Done Gate

Passkey warm-session unseal-handle hardening is implemented. The product path
stays lazy: unlock authorizes the wallet/session and may install a one-use
unseal authorization inside the credential-confirm worker, and the first signing
operation restores worker material only when it actually needs the sealed
Ed25519 artifact. Email OTP/recovery-code unlock install remains optional unless
that unlock ceremony starts collecting recovery-code material.

Before calling Refactor 74 done, these release gates must be closed or
explicitly evidenced:

- Add-signer/device-sync sealed artifact evidence: implementation routes flows
  that create or refresh Ed25519 signing material through the same sealed
  worker-material artifact/reference, `materialKeyId`, material binding digest,
  AAD format, and material facts as registration/repair. Evidence:
  `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` audits registration
  add-signer, link-device, sync-account, and email-recovery sync call paths; the
  add-wallet-signer unit coverage checks the later-Ed25519 path uses worker
  material handle/binding fields.
- Email OTP recovery-code boundary evidence: Email OTP account control can
  authorize the flow, but direct Ed25519 restore requires an opaque recovery-code
  `unseal` capability. Evidence:
  `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` rejects raw
  recovery-code bytes in the signing restore resolver, and
  `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts` covers the
  opaque Email OTP unseal authorization branch.
- Transaction-flow material restore evidence:
  `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts` covers a
  `material_pending`/restore-available Ed25519 record reaching
  `persistStoredThresholdEd25519SessionMaterialHandle()` before Router A/B
  normal signing, without HSS or raw-material fallback. Keep this as release
  evidence; additional browser evidence remains separate.
- Raw PRF, HSS-name, and deterministic-handle cleanup evidence: remaining
  `prfFirstB64u` and HSS names are classified as setup/export/credential
  boundary markers. Active source and fixtures no longer contain the deleted
  direct PRF claim method, old Ed25519 HSS material field names, the old
  HSS-shaped material-ref discriminant, or deterministic HSS material-handle
  fixture strings. Evidence:
  `tests/unit/refactor74LoginNoHss.guard.unit.test.ts`.
- Browser evidence: complete after Refactor 70 landed. The combined browser
  path proves no-HSS unlock, lazy worker-material restore, NEAR transaction
  signing, NEP-413 signing, delegate signing, and server-authoritative budget
  exhaustion behavior together.
  - Harness coverage now lives in
    `tests/e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`: one path
    covers shared NEAR/Tempo/EVM budget exhaustion, and one path covers NEAR
    transaction, NEP-413, delegate signing, lazy Ed25519 restore, and exhaustion.
  - Current local rerun status: complete. Command:
    `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`.
    Latest local result: `2 passed`.
  - Focused Ed25519 evidence command:
    `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts -g "one unlock lazily restores Ed25519 material"`.
    Latest local result: `1 passed`.

## Migration Notes

This is an internal lifecycle cleanup during development. Breaking changes are
allowed.

Delete obsolete eager-HSS unlock assumptions. If any persisted records encode
old material-ready expectations, parse them once at the persistence boundary
into the new authorization/material state split, then remove the obsolete branch
after the replacement is complete.

## Completion Criteria

- `unlock()` succeeds for Ed25519 warm sessions without running Ed25519 HSS.
- Unlock latency no longer includes Ed25519 HSS material reconstruction.
- First Ed25519 signing operation validates or restores signer-core material
  before producing a signature, without invoking HSS.
- First Ed25519 signing with a valid sealed material artifact restores through
  `RestoreThresholdEd25519WorkerMaterial` and persists the loaded handle.
- First Ed25519 signing with no sealed material artifact returns
  `material_restore_required`.
- First Ed25519 signing with no active unseal authorization returns
  `material_unseal_authorization_required`.
- Durable worker material is sealed with passkey PRF or recovery-code-derived
  material through a purpose-scoped `seal` authorization handle, not with HSS
  output-mask bytes.
- Setup obtains `materialKeyId` and `sealAuthorization` from the
  signer-core/WASM credential-boundary issuer; store returns
  `materialBindingDigest`, `clientVerifyingShareB64u`, and durable sealed
  material facts after opening HSS output inside WASM. Core TypeScript does not
  derive the setup verifier from `prfFirstB64u`.
- Restore obtains `unsealAuthorization` from the signer-core/WASM
  credential-boundary issuer; core TypeScript does not claim, cache, or route
  raw PRF/recovery-code material for normal Ed25519 signing.
- Active setup, restore, warm-session hydration, unlock, and signing code
  outside credential-boundary adapters has no `prfFirstB64u`,
  `recoveryCodeSecret32B64u`, raw PRF bytes, recovery-code secret bytes, or
  derived seal/unseal key fields.
- Core SDK, persistence, route-client, warm-session, and signing code cannot
  construct secret-bearing material authorization requests with `prfFirstBytes`
  or `recoveryCodeSecret32`.
- Final worker command types do not expose `clientOutputMaskB64u`; HSS output
  masks are one-use Rust-owned handles by default, with transient `Uint8Array`
  transport allowed only for a proven byte-capable worker-local path.
- v1 `seal` and `unseal` handles are one-use, default to a 60-second TTL, and
  reject lifetimes above the 5-minute cap unless a typed server-authorized
  capability branch is added.
- Server policy remains authoritative for Wallet Session, Signing Grant,
  server-side budget, route authorization, transaction policy, and step-up
  requirements. Worker material handles only authorize local seal/unseal of
  one scoped MPC artifact.
- Error mapping preserves the domain split between warm-session
  `unseal_authorization_required` and worker material
  `material_unseal_authorization_required`.
- Logs no longer show Ed25519 HSS material-handle ceremony timings during
  ordinary wallet unlock or normal transaction signing.
- Tests cover `material_pending` unlock and lazy signing materialization.
- TypeScript carries opaque material handles and public binding facts only;
  signer-core/WASM owns crypto operations and raw material.

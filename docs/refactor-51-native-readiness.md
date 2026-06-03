# Refactor 51 Native Readiness

This document is the Phase 10 handoff for future iOS and Linux/embedded
adapters. The current completed surface is ECDSA HSS client bootstrap through
signer-core prepare/finalize commands, plus signer-core ECDSA role-local export
artifact construction. Refactor 51 native-readiness acceptance is complete after
the Phase 9 compatibility deletion and data reset cleanup recorded in
`docs/refactor-51-cross-platform-2.md`.

## Canonical Artifacts

| Area | Canonical artifact |
| --- | --- |
| Rust command structs | `crates/signer-core/src/commands/ecdsa_bootstrap.rs`, `crates/signer-core/src/commands/ecdsa_export.rs` |
| Generated TypeScript command schemas | `client/src/core/platform/generated/signerCoreCommands.ts` |
| Schema drift test | `crates/signer-core/tests/export_typescript_schemas.rs` |
| Native replay fixture | `crates/signer-core/fixtures/native-readiness/ecdsa-bootstrap-v1.json` |
| Native replay test | `crates/signer-core/tests/native_readiness_vectors.rs` |
| Browser adapter conformance baseline | `tests/unit/platformAdapter.conformance.unit.test.ts` |
| Web/native facade split plan | `docs/refactor-51b-cross-platform-3.md` |

Regenerate the replay fixture only when the command contract intentionally
changes:

```bash
UPDATE_NATIVE_READINESS_VECTORS=1 cargo test \
  --manifest-path crates/signer-core/Cargo.toml \
  --features threshold-ecdsa-hss,typescript-bindings \
  --test native_readiness_vectors
```

Then run the replay test without the update flag.

## Schema Coverage

| Native adapter need | Current command coverage | Remaining gap |
| --- | --- | --- |
| Build an ECDSA role-local pending state blob from a passkey PRF output | `PrepareEcdsaClientBootstrapCommandV1` with `webauthn_prf_first` secret source | Native platforms must supply a normalized PRF-equivalent secret at the boundary. |
| Carry Email OTP bootstrap handles through command-shaped contracts | `EcdsaBootstrapSecretSourceV1::EmailOtpWorkerSession` and generated schemas | The command intentionally returns unsupported until the Email OTP worker resolves the handle internally. |
| Finalize pending ECDSA role-local state with relayer public identity | `FinalizeEcdsaClientBootstrapCommandV1` | None for bootstrap finalize. |
| Persist ECDSA role-local blobs across platforms | `EcdsaRoleLocalPendingStateBlobV1` and `EcdsaRoleLocalReadyStateBlobV1` envelopes | Native adapters must treat the envelope payloads as opaque durable values. |
| Preserve command and invocation error categories | signer-core error codes plus platform `SignerCryptoPort` failure categories | Native adapters must map binding failures to invocation errors and signer-core failures to command errors. |
| Export ECDSA ready blobs from native bindings | `BuildEcdsaRoleLocalExportArtifactCommandV1` | Add replay fixtures before shipping a native export binding. |
| Sign and restore ECDSA ready blobs from native bindings | Browser signing opens ready-state blobs through the hss-client worker; restore is covered by platform durable-record conformance | Future native adapters need platform-specific binding and conformance coverage for signing and restore. |

State blob payloads are opaque. Platform adapters may store and transport the
base64url envelopes, and core logic should never decode the inner payload outside
signer-core-owned commands.

## Adapter Conformance

Every native adapter must pass the shared port conformance suite that the browser
adapter uses today, plus the signer-core replay fixture in this document.

Required checks before a native adapter release:

- Generated schema drift test passes for every command the adapter calls.
- Native replay fixtures pass through the exact binding surface shipped by the
  adapter.
- `AuthenticatorPort`, `SignerCryptoPort`, `DurableRecordStore`, and
  `HttpTransport` conformance cases pass for the platform adapter.
- Binding failures are represented as invocation failures, and signer-core
  validation/crypto failures preserve signer-core command error codes.
- Raw ECDSA role-local share fields never cross the platform adapter boundary.

## iOS Adapter Requirements

The iOS adapter should expose the existing platform ports through Swift-native
implementations and keep signer-core as the owner of ECDSA HSS command logic.

| Port | Requirement |
| --- | --- |
| `AuthenticatorPort` | Use AuthenticationServices/passkey APIs for user presence and credential discovery. PRF-equivalent output must be normalized once at the boundary before building signer-core commands. If the OS cannot provide the required PRF material, return a typed unsupported result. |
| `SignerCryptoPort` | Call signer-core through a native binding. The binding input/output must match generated command schemas, and the ECDSA bootstrap vector must replay exactly. |
| `DurableRecordStore` | Store versioned records atomically in a Keychain-backed or encrypted app database path. Persist ECDSA state blob envelopes as opaque values. |
| `HttpTransport` | Use the native HTTPS client with explicit request timeouts, cancellation propagation, and the same relayer request/response boundary parsers used by browser code. |
| Secret storage | Store platform secrets in Keychain with access controls appropriate to the wallet lifecycle. Logs, analytics, crash reports, and diagnostics must omit PRF outputs, root shares, state blob payloads, and raw relayer material. |
| Lifecycle | Handle app backgrounding, biometric cancellation, passkey sheet cancellation, network retry, and process restart without widening internal domain types to partial lifecycle states. |

## iOS RP ID And Web Boundary

The browser wallet runtime is origin-isolated today because the browser uses the
wallet iframe as a separate origin-owned execution surface. Native adapters
should translate that requirement into platform isolation: app sandboxing,
Keychain access control, AuthenticationServices passkey ceremony ownership, and
signer-core bindings behind the platform ports. The iframe is a browser facade
detail.

The public web facade should be treated as `SeamsWeb` after the Refactor 51b
split. It owns browser-only concerns: DOM availability, React integration, the
wallet iframe coordinator, browser WebAuthn prompts, browser IndexedDB adapters,
and iframe message routing. Native iOS and Linux/embedded packages must have
zero imports from `SeamsWeb`, `WalletIframeRouter`, `WalletIframeCoordinator`,
React, DOM modules, and iframe route definitions.

iOS passkeys should use the service domain as the relying party ID. The app name
and bundle ID identify the app, while the WebAuthn relying party remains
`seams.sh` when interoperability with the web wallet is required.

Required iOS passkey contract:

- The iOS `AuthenticatorPort` uses AuthenticationServices, with
  `ASAuthorizationPlatformPublicKeyCredentialProvider` configured for
  `seams.sh`.
- The app entitlement includes the Associated Domains entry
  `webcredentials:seams.sh`.
- `https://seams.sh/.well-known/apple-app-site-association` lists the app ID
  under its `webcredentials` section.
- Server verification accepts native iOS ceremonies only when the WebAuthn
  artifacts bind to the expected `seams.sh` RP ID hash and the expected native
  origin policy for the registered app.
- Boundary parsers must normalize native AuthenticationServices responses into
  the same internal credential-result shape used by browser WebAuthn before
  core lifecycle or signing code sees them.

`WKWebView` and `ASWebAuthenticationSession` can be used for account linking or
temporary integration flows when a product surface requires web continuity. They
do not define the SDK architecture. Native adapters should call the platform
ports directly and should never route signing, restore, export, or durable-store
operations through the wallet iframe.

Reference material:

- Apple AuthenticationServices relying party identifier:
  https://developer.apple.com/documentation/authenticationservices/asauthorizationplatformpublickeycredentialprovider/relyingpartyidentifier
- Apple Associated Domains:
  https://developer.apple.com/documentation/Xcode/supporting-associated-domains
- Apple passkey app integration sample:
  https://developer.apple.com/documentation/authenticationservices/connecting_to_a_service_with_passkeys
- W3C WebAuthn relying party ID and `rpIdHash`:
  https://w3c.github.io/webauthn/

## Linux/Embedded Adapter Requirements

The Linux/embedded adapter should use the same signer-core command contracts and
choose storage/auth mechanisms appropriate to the device class.

| Port | Requirement |
| --- | --- |
| `AuthenticatorPort` | Use FIDO2 hmac-secret/PRF, TPM-backed secrets, or another reviewed platform secret source. Normalize the result into the signer-core secret-source shape at the boundary. Unsupported hardware returns a typed unsupported result. |
| `SignerCryptoPort` | Call signer-core through a native Rust crate, C ABI, or authenticated local daemon. The shipped invocation surface must replay the ECDSA bootstrap vector exactly. |
| `DurableRecordStore` | Use SQLite or filesystem records with atomic write/replace, fsync where available, corruption handling, and versioned boundary parsers. |
| `HttpTransport` | Use a TLS stack with a maintained root store, bounded timeouts, retry policy owned by the transport layer, and structured relayer errors. |
| Secret storage | Prefer TPM2, kernel keyring, libsecret, or hardware-backed storage where available. File-backed storage must be encrypted and permission-restricted. |
| Resource profile | Keep command payloads bounded, avoid long-lived raw secret buffers, and run replay vectors on the lowest supported CPU class. |

## Future Platform Gaps

Phase 10 artifacts are in place for the Refactor 51 browser cutover. Future
native adapter work should address these platform-specific gaps before a native
release:

- add replay fixtures for every signer-core command a native adapter calls,
  including ECDSA export when native export is enabled.
- define the native ECDSA signing binding surface for ready-state blobs and add
  conformance coverage for invocation and command-failure mapping.
- define platform-specific restore persistence behavior for iOS and
  Linux/embedded durable stores.
- add an iOS Associated Domains fixture for the canonical `seams.sh` RP ID and
  expected app ID.
- define native-app expected-origin verification fixtures for WebAuthn server
  validation.
- add guard tests proving native and embedded packages have zero imports from
  `SeamsWeb`, wallet iframe routing, React, DOM modules, and browser IndexedDB
  adapters.
- add an embedded isolation note for each supported device class, covering the
  process boundary, storage boundary, and hardware-backed secret source used in
  place of browser origin isolation.
- keep Email OTP worker-session handles browser-owned unless a native Email OTP
  worker or equivalent platform handle is explicitly specified.

Future platform work should add one replay fixture per new signer-core command
and one adapter conformance case for each new platform port behavior.

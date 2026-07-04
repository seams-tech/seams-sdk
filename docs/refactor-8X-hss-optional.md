# Optional HSS Bootstrap Profiles

Date created: June 8, 2026

Status: planning.

## Goal

Make HSS an explicit signing-bootstrap profile instead of a universal
registration requirement.

Browser-hosted wallets should keep HSS as the default high-assurance bootstrap
because browser storage, iframe isolation, and origin boundaries are weaker than
native platform trust roots. iOS, embedded, and other native runtimes should be
able to use simpler local or hardware-backed Ed25519 bootstrap profiles when
their platform security model is stronger and lower-latency.

The long-term gold standard is still fast HSS. Optional profiles are a platform
and trust-model design, not a reason to stop improving HSS performance.

## Relationship To Existing Plans

- `docs/refactor-51-native-readiness.md` owns native platform adapter
  boundaries: authenticator ports, signer crypto ports, durable stores,
  transport, and secret storage.
- `docs/refactor-55-hss-optimize-registration.md` owns HSS registration
  performance work.
- `docs/refactor-59-optimize.md` owns full registration benchmarking and the
  measured `1500ms` target gap.
- `docs/refactor-64-hss-protocol-runtime-latency.md` owns the fast-HSS runtime
  and protocol optimization track.
- This plan owns the policy and product shape for making HSS optional outside
  browser contexts.

## Current Read

Current registration assumes Ed25519 HSS bootstrap for the threshold Ed25519
signing path. Recent benchmark work shows this is one of the largest
registration latency buckets:

- HSS client evaluation artifact: about `677ms` p50 in the latest smoke report
- `/wallets/register/start`: about `380ms` p50, dominated by HSS prepare
- `/wallets/register/finalize`: about `467ms` p50, dominated by HSS finalize

This is appropriate for browser wallet assurance, where HSS reduces server
custody risk while keeping the browser client from holding a relayer-known final
secret.

iOS and embedded runtimes have different primitives:

- app sandboxing
- Keychain or platform secure storage
- Secure Enclave or secure element keys where available
- native Rust signer runtime without iframe transport
- device-local durable storage under a narrower platform adapter
- possible attestation for higher-assurance devices

Those runtimes should select a bootstrap profile deliberately. The server and
SDK must record the trust decision, enforce it at route boundaries, and present
it clearly to app developers.

## Trust Model

Every bootstrap profile must answer:

- who can cause a valid signature
- whether the server can unilaterally sign
- whether live user authorization is required
- what local compromise exposes
- what server compromise exposes
- whether recovery keeps the same assurance level
- whether the profile supports browser, iOS, embedded, or server-only runtimes

No profile may silently downgrade an existing wallet. Profile changes require an
explicit add-signer or rotation ceremony.

## Target Domain Types

The SDK should model bootstrap selection as a discriminated union with required
branch fields.

```ts
type SigningBootstrapProfile =
  | ThresholdEd25519HssBootstrapProfile
  | LocalDeviceEd25519BootstrapProfile
  | HardwareBackedEd25519BootstrapProfile
  | AttestedDeviceEd25519BootstrapProfile
  | ServerManagedEd25519BootstrapProfile;

type ThresholdEd25519HssBootstrapProfile = {
  kind: 'threshold_ed25519_hss';
  defaultRuntime: 'browser_wallet_iframe' | 'host_origin' | 'native';
  trustModel: 'threshold_client_server';
  requiresFreshUserAuthorization: true;
  recoveryModel: 'threshold_restore' | 'email_otp_recovery_codes';
};

type LocalDeviceEd25519BootstrapProfile = {
  kind: 'local_device_ed25519';
  defaultRuntime: 'ios' | 'embedded' | 'desktop_native';
  trustModel: 'device_local_secret';
  secretStore: 'keychain' | 'encrypted_file_store' | 'platform_secure_store';
  requiresFreshUserAuthorization: boolean;
  recoveryModel: 'device_backup' | 'manual_export' | 'none';
};

type HardwareBackedEd25519BootstrapProfile = {
  kind: 'hardware_backed_ed25519';
  defaultRuntime: 'ios' | 'embedded';
  trustModel: 'hardware_backed_local_secret';
  hardwareClass: 'secure_enclave' | 'secure_element' | 'hardware_wallet';
  requiresFreshUserAuthorization: boolean;
  recoveryModel: 'hardware_backup' | 'manual_export' | 'none';
};

type AttestedDeviceEd25519BootstrapProfile = {
  kind: 'attested_device_ed25519';
  defaultRuntime: 'ios' | 'embedded';
  trustModel: 'attested_hardware_or_runtime';
  attestationScheme: 'apple_app_attest' | 'android_key_attestation' | 'custom_device_attestation';
  requiresFreshUserAuthorization: boolean;
  recoveryModel: 'attested_reenrollment' | 'manual_export' | 'none';
};

type ServerManagedEd25519BootstrapProfile = {
  kind: 'server_managed_ed25519';
  defaultRuntime: 'server';
  trustModel: 'server_can_sign_under_policy';
  requiresFreshUserAuthorization: boolean;
  recoveryModel: 'server_policy_recovery';
};
```

Core functions should accept the narrow profile branch they need. Raw route
bodies, DB records, and persisted wallet metadata should parse into this union
at the boundary.

## Profile Policy

Initial policy:

- Browser wallet iframe: `threshold_ed25519_hss` by default.
- Browser host-origin development mode: `threshold_ed25519_hss` by default.
- iOS native: `hardware_backed_ed25519` preferred when available,
  `local_device_ed25519` allowed by app policy, HSS allowed as a high-assurance
  option.
- Embedded: `hardware_backed_ed25519` or `local_device_ed25519` preferred by
  default, HSS allowed only when the device benchmark clears latency and memory
  gates.
- Server-managed wallets: explicit `server_managed_ed25519` profile with
  separate product copy and account metadata.

Policy must be explicit in:

- SDK registration options
- wallet metadata
- relay registration intent
- relay wallet record
- signer record
- add-signer and rotation flows
- exported diagnostics and support tooling

## UX Requirements

The UI should expose the profile as an assurance choice only where the app has a
real choice to make.

Required product copy:

- HSS profile: "Threshold protected. Server cannot sign alone."
- Local device profile: "Stored on this device. Device backup controls
  recovery."
- Hardware-backed profile: "Protected by device hardware where available."
- Attested device profile: "Device-bound and attested by platform policy."
- Server-managed profile: "Managed by server policy."

The SDK should give app developers a simple default per platform. Advanced apps
can override the profile through typed options.

## Server Requirements

Registration routes must bind the selected profile into:

- registration intent digest
- wallet registration ceremony id
- account id and wallet id
- signer mode
- auth method
- runtime policy scope
- recovery policy
- signer record

Server validation must reject:

- profile omitted at a route where multiple profiles are enabled
- unsupported profile for the runtime policy
- HSS fields on a local or hardware-backed profile
- local-device key fields on an HSS profile
- server-managed profile without explicit server policy configuration
- attempts to rotate from one profile to another without an add-signer or
  signer-rotation ceremony

## Client Requirements

The client must keep branch-specific state:

- HSS profile owns HSS prepare/respond/finalize state.
- Local device profile owns local key generation and durable secret storage.
- Hardware-backed profile owns platform key creation and signing handle
  persistence.
- Attested device profile owns attestation evidence and platform key binding.
- Server-managed profile owns server policy proof and user consent state.

Shared registration code should operate on a narrow prepared signer result:

```ts
type PreparedRegistrationSigner =
  | {
      kind: 'threshold_ed25519_hss';
      hssRegistrationResult: HssRegistrationResult;
    }
  | {
      kind: 'local_device_ed25519';
      publicKey: string;
      secretRecordId: string;
    }
  | {
      kind: 'hardware_backed_ed25519';
      publicKey: string;
      hardwareKeyHandleId: string;
    }
  | {
      kind: 'attested_device_ed25519';
      publicKey: string;
      hardwareKeyHandleId: string;
      attestationRecordId: string;
    }
  | {
      kind: 'server_managed_ed25519';
      publicKey: string;
      serverPolicyId: string;
    };
```

## Phase 0: Inventory Current HSS Assumptions

Goal:

- find every place registration assumes HSS is mandatory

Tasks:

- [ ] inventory SDK registration inputs and signer-selection types
- [ ] inventory relay registration route bodies and response shapes
- [ ] inventory wallet and signer durable records
- [ ] inventory wallet-iframe messages and worker requests
- [ ] inventory recovery and rotation flows that assume HSS enrollment
- [ ] inventory tests and fixtures that encode HSS-only registration behavior
- [ ] document which assumptions are browser-specific and which are true signer
      requirements

Validation:

- `rg "hss|threshold_ed25519|ed25519" client server tests docs`

## Phase 1: Define Bootstrap Profile Boundary Types

Goal:

- introduce the profile union at SDK, route, and persistence boundaries

Tasks:

- [ ] add core profile types with discriminated unions and required fields
- [ ] add route-boundary parsers for untrusted profile input
- [ ] add persisted-record parsers for wallet and signer metadata
- [ ] add type fixtures rejecting invalid profile combinations
- [ ] keep compatibility parsing only at persistence/request boundaries
- [ ] delete any duplicate legacy branch once the new profile is authoritative

Validation:

- `pnpm -C sdk type-check`
- targeted unit tests for profile parsing and type-level rejection

## Phase 2: Browser HSS Default

Goal:

- preserve current browser assurance while making the profile explicit

Tasks:

- [ ] make browser registration select `threshold_ed25519_hss` explicitly
- [ ] bind the profile into registration intent and relay ceremony state
- [ ] reject profile mismatch across `/wallets/register/start`,
      `/wallets/register/hss/respond`, and `/wallets/register/finalize`
- [ ] define replacement registration latency evidence on the real
      intended-behaviour topology; the old `benchmark:registration-flow`
      runner was retired by Refactor 88 with its managed-registration mock
      harness
- [ ] update diagnostics to include sanitized profile kind

Validation:

- `pnpm -C sdk type-check`
- focused registration orchestration tests
- replacement real-topology registration latency benchmark once available

## Phase 3: Local Device Profile

Goal:

- add a native-friendly local Ed25519 bootstrap profile without HSS ceremony

Tasks:

- [ ] define `local_device_ed25519` registration input
- [ ] generate Ed25519 material through the platform signer crypto port
- [ ] persist the local secret handle through the platform durable store
- [ ] send only the public key and profile metadata to the relay
- [ ] add signer records that distinguish local-device signers from HSS signers
- [ ] implement signing readiness checks for local-device signers
- [ ] add tests proving HSS route fields are rejected for local-device
      registration

Validation:

- `pnpm -C sdk type-check`
- targeted local-device registration tests
- signing readiness tests for local-device signer records

## Phase 4: Hardware-Backed Profile

Goal:

- add a profile for platform or device hardware-backed Ed25519 keys

Tasks:

- [ ] define the platform capability contract for hardware-backed key creation
- [ ] define how public keys, key handles, and access-control policy are stored
- [ ] bind hardware-backed profile metadata into signer records
- [ ] define fallback behavior when hardware Ed25519 is unavailable
- [ ] add tests for unsupported-platform rejection
- [ ] add iOS adapter notes once the native contract is implemented

Validation:

- SDK type-check
- platform-adapter contract tests

## Phase 5: Attested Device Profile

Goal:

- add an explicit profile for devices that can prove key origin or runtime
  integrity

Tasks:

- [ ] define accepted attestation schemes
- [ ] define attestation verification route and durable record shape
- [ ] bind attestation result to wallet id, signer id, account id, public key,
      app id, device id, and expiry
- [ ] define reattestation and rotation rules
- [ ] reject stale, mismatched, or unsupported attestations

Validation:

- route parser tests
- attestation verification tests with fixtures

## Phase 6: Server-Managed Profile

Goal:

- make custodial or policy-managed signing explicit when a product chooses it

Tasks:

- [ ] define `server_managed_ed25519` as a separate account policy
- [ ] require explicit server policy id and user consent state
- [ ] ensure UI and SDK copy clearly describe server-managed authority
- [ ] prevent accidental creation through default registration
- [ ] add tests proving browser HSS defaults never select this profile

Validation:

- route-policy tests
- SDK type-check

## Phase 7: Recovery And Rotation

Goal:

- make recovery behavior profile-specific

Tasks:

- [ ] map recovery options for every bootstrap profile
- [ ] define add-signer flows across profiles
- [ ] define rotation from HSS to local or hardware-backed signers
- [ ] define rotation from local or hardware-backed signers to HSS
- [ ] require explicit user authorization for profile changes
- [ ] record profile history in diagnostics or audit metadata

Validation:

- add-signer route tests
- rotation tests
- recovery UI tests where applicable

## Phase 8: Benchmark And Device Suitability

Goal:

- decide where HSS remains acceptable by performance and memory budget

Tasks:

- [ ] benchmark browser HSS registration with current `refactor-59` harness
- [ ] benchmark native Rust HSS registration outside browser/WASM
- [ ] benchmark local-device profile registration
- [ ] benchmark hardware-backed profile registration where available
- [ ] capture peak memory and payload sizes
- [ ] run a low-power device or throttled CPU profile
- [ ] record platform recommendations in this plan

Acceptance targets:

- browser HSS keeps improving toward the `1500ms` registration target
- local and hardware-backed profiles avoid HSS ceremony latency on native
  devices
- embedded recommendation is based on measured compute, memory, and payload
  costs

## Open Questions

- Should browser host-origin development mode ever allow local-device bootstrap,
  or should it mirror wallet-iframe HSS to keep tests representative?
- Which native platforms can create hardware-backed Ed25519 keys directly?
- Do we need a separate secp256k1 or ECDSA bootstrap profile for EVM-first
  products?
- Should profile choice be app-configured, user-visible, or both?
- How much signer-profile detail should be exposed through public account APIs?
- What is the minimum metadata needed for support and audits without leaking
  device-sensitive details?

## Keep And Revert Rules

Keep a profile implementation only if:

- the trust statement is explicit
- invalid state is rejected by types or boundary parsers
- server routes bind the profile into registration and signer records
- recovery and rotation behavior is defined
- browser HSS default remains intact
- benchmark or product value justifies the added branch

Revert or redesign if:

- profile selection can silently downgrade assurance
- HSS and local-device fields can mix in one internal state
- compatibility logic leaks past route or persistence boundaries
- account metadata cannot explain who can sign
- native support adds browser-iframe concepts to platform adapters

# OTP WASM Worker Refactor Plan

Date updated: April 15, 2026

## Objective

Move the Email OTP runtime out of JS main-thread orchestration and into a dedicated WASM-backed worker runtime.

After this refactor:

1. the JS main thread keeps only superficial product orchestration concerns
2. the worker owns all secret-bearing Email OTP logic
3. recovered secret `S` is unsealed and consumed inside worker-owned runtime state
4. `WarmSessionManager` remains on the JS main thread for policy decisions and warm-session lifecycle
5. legacy main-thread OTP secret plumbing is removed rather than retained behind compatibility layers

## Current Status

This refactor has not started implementation yet.

What is already complete:

1. the refactor plan exists
2. the current core OTP system has already completed a separate hardening pass:
   - byte-owned recovered-secret handling
   - byte-oriented `shamir3pass` worker and WASM entrypoints
   - opaque worker-held `shamir3pass` key handles
   - stronger `WarmSessionManager` policy handling for Email OTP
3. that hardening work is a prerequisite and design input for this refactor, but it is not the refactor itself
4. the prerequisite core release-gate validation has been rerun successfully after the latest handle-only cleanup

What is not started yet:

1. there is no dedicated `emailOtp` worker
2. Email OTP networking still lives on the main-thread orchestration side
3. Email OTP login, unlock, enrollment, and bootstrap flows have not yet moved behind a dedicated worker boundary
4. `wasm/email_otp_runtime` does not exist yet

Concrete residuals confirmed by the latest audit:

1. [emailOtp.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/emailOtp.ts) still owns main-thread secret-bearing route composition and unlock-proof orchestration
2. [emailOtp.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/emailOtp.ts) still exposes string-secret compatibility/public helper entrypoints such as `completeEmailOtpUnlock(...clientSecretB64u)` and optional caller-supplied `clientSecretB64u` enrollment input
3. [emailOtpDerivation.ts](/Users/pta/Dev/rust/simple-threshold-signer/shared/src/utils/emailOtpDerivation.ts) still performs the OTP HKDF derivation in JS rather than in worker-owned WASM

## Scope Split

### Keep on JS main thread

These are allowed to remain in JS main-thread code:

1. UI state and OTP input handling
2. app/session routing
3. public SDK method entrypoints and argument validation
4. `WarmSessionManager` policy decisions
5. high-level auth flow composition
6. non-secret result handling for UI and app state

### Move into dedicated worker-owned runtime

These should move behind a dedicated OTP worker boundary:

1. relayer networking for Email OTP flows
2. `shamir3pass` key generation, wrap, and unwrap calls
3. recovered secret `S` handling
4. Email OTP HKDF derivation from `S`
5. unlock key derivation
6. unlock proof generation
7. enrollment sealing flow
8. login plus unseal flow
9. login plus unlock flow
10. login plus ECDSA bootstrap preparation flow
11. secret zeroization and ownership enforcement

## Security Goal

The refactor is not about performance first. It is about reducing the number of JS main-thread locations that ever observe or retain secret-bearing material.

The target security model is:

1. `S` is decrypted only inside a worker-owned runtime
2. `S` is represented as bytes, not long-lived strings, wherever practical
3. HKDF intermediates and derived secret branches are zeroized inside the worker after final use
4. the main thread receives only the minimum result data required to continue the product flow

This is stronger than the current model because it reduces accidental main-thread retention, logging risk, string-backed secret propagation, and secret round-trips across multiple runtime layers.

## Target Architecture

### New worker

Add a dedicated worker kind:

1. `emailOtp`

This worker should initialize and own:

1. `shamir3pass_runtime`
2. `eth_signer`
3. a new `email_otp_runtime` WASM module for byte-oriented derivation

### Worker-owned modules

The intended module split is:

1. `shamir3pass_runtime`
   - client seal key generation
   - wrap and unwrap math
2. `email_otp_runtime`
   - decode `S`
   - derive threshold root
   - derive client root share
   - derive unlock auth seed
   - zeroize OTP-specific intermediates
3. `eth_signer`
   - secp256k1 public key derivation
   - unlock challenge signing
   - any other secp256k1 helper already used by OTP paths

### Main-thread shape after refactor

Main-thread OTP entrypoints should become thin facades:

1. validate public arguments
2. invoke one worker operation
3. receive sanitized result
4. hand non-secret outputs into `WarmSessionManager` or session bootstrap orchestration

The main thread should no longer directly:

1. call `getShamir3PassRuntime()` for Email OTP runtime flows
2. derive Email OTP secrets from recovered `S`
3. assemble secret-bearing Email OTP HTTP payloads
4. create unlock proofs from secret-derived material
5. receive raw `clientSecretB64u`

## Worker-owned Networking

Email OTP networking should move into the worker so the secret-bearing flow stays in the same runtime that owns unseal and derivation.

### Routes owned by worker

The worker should directly call:

1. `/wallet/email-otp/challenge`
2. `/wallet/email-otp/verify`
3. `/wallet/email-otp/unseal`
4. `/wallet/email-otp/enroll/challenge`
5. `/wallet/email-otp/enroll/seal`
6. `/wallet/email-otp/enroll/verify`
7. `/wallet/unlock/challenge`
8. `/wallet/unlock/verify`

### Networking rules

1. support both cookie and bearer-token auth where the current runtime does
2. normalize relayer errors in the worker before returning them to main thread
3. keep request-body assembly for secret-bearing routes inside the worker
4. do not bounce relayer payloads through main-thread helpers if the worker can submit them directly

## Worker API Shape

Prefer high-level operation APIs rather than exposing primitive worker RPC methods.

### Required worker operations

1. `emailOtpEnroll`
   - request enrollment challenge
   - generate or accept enrollment secret source
   - perform client seal flow
   - derive unlock public key
   - derive threshold verifying share
   - submit enrollment verify
   - return sanitized enrollment result
2. `emailOtpLoginAndUnlock`
   - request challenge
   - verify OTP
   - request unseal
   - unwrap secret inside worker
   - derive unlock proof
   - fetch unlock challenge
   - sign challenge
   - submit unlock verify
   - return sanitized unlock result
3. `emailOtpLoginAndBootstrapEcdsa`
   - perform full login plus unlock sequence
   - derive ECDSA bootstrap inputs inside worker
   - return final bootstrap-ready result with minimum necessary fields
4. `emailOtpRequestChallenge`
   - optional helper only if product flow needs a separate challenge step at UI layer

### API design rule

Do not expose worker operations that return raw recovered `S` to the main thread.

## Byte Ownership Model

### Core rules

1. secret-bearing data should use `Uint8Array` or worker-owned WASM memory while in runtime
2. base64url strings are allowed only at external boundaries
3. every secret-bearing owned buffer must have one clear owner and one clear zeroization point
4. worker outputs should be public or minimally necessary derived values only

### External-boundary exceptions

Base64url is still acceptable for:

1. HTTP payloads required by current relayer routes
2. persisted public metadata
3. transitional outputs where a downstream consumer still requires base64url

These exceptions should be treated as migration boundaries, not internal runtime storage strategy.

## Proposed WASM Additions

Create a new crate:

1. `wasm/email_otp_runtime`

### Responsibilities

1. decode `clientSecretB64u` into secret bytes
2. implement canonical HKDF-SHA-256 derivation for OTP branches
3. expose byte-oriented APIs for:
   - threshold root
   - threshold ECDSA client root share
   - unlock auth seed
4. zeroize:
   - decoded secret
   - PRK
   - threshold root
   - temporary tuple/info buffers where owned
   - any other owned secret intermediates

### Reason for separate module

This keeps OTP-specific derivation logic out of shared JS helpers and makes the worker runtime the only place where recovered `S` is consumed.

## Refactor Phases

### Phase 0: Planning and prerequisite hardening

Completed:

1. write the worker-refactor plan
2. harden the current core Email OTP implementation so the later worker split has a cleaner baseline
3. remove the app-facing legacy `shamir3pass` keypair path in favor of worker-held key handles

### Phase 1: Add worker transport and runtime scaffold

1. add new `emailOtp` worker kind
2. add worker transport and request/response types
3. add worker lifecycle, initialization, timeout, and error handling
4. add worker-side fetch helper with consistent auth and error normalization

Done criteria:

1. main thread can dispatch Email OTP operations through the new worker
2. no OTP-specific worker transport code is embedded ad hoc in unrelated workers

### Phase 2: Move `shamir3pass` ownership into OTP worker

1. initialize `shamir3pass_runtime` inside the OTP worker
2. remove direct Email OTP runtime dependence on main-thread `getShamir3PassRuntime()`
3. perform wrap and unwrap entirely in worker-owned flow
4. keep wrapped and unwrapped intermediate values inside the worker

Done criteria:

1. Email OTP runtime no longer unwraps secret `S` through main-thread helper code
2. `clientSecretB64u` is not returned from worker to main thread

### Phase 3: Move OTP derivation into WASM

1. add `email_otp_runtime` crate
2. port tuple encoding and HKDF derivation logic from JS helper code
3. expose byte-oriented derivation APIs
4. add zeroization on success and error paths
5. make worker use WASM derivation instead of JS shared derivation helpers

Done criteria:

1. Email OTP derivation is no longer performed by main-thread JS helper code in runtime path
2. worker owns derivation of unlock auth seed and client root share

### Phase 4: Move unlock proof generation fully into worker

1. derive unlock private key in worker-owned runtime
2. call secp256k1 pubkey derivation in worker
3. fetch unlock challenge in worker
4. sign challenge in worker
5. submit unlock verify in worker
6. return only sanitized unlock result

Done criteria:

1. main thread no longer assembles unlock proof flow from secret-bearing inputs
2. unlock key material never leaves worker-owned runtime

### Phase 5: Move enrollment flow fully into worker

1. move enrollment challenge request into worker
2. move seal request into worker
3. move enrollment secret generation or acceptance into worker-owned flow
4. derive unlock and verifying material in worker
5. submit enrollment verify in worker
6. return only final enrollment result

Done criteria:

1. `enrollEmailOtpWallet` is reduced to a thin facade
2. enrollment secret handling never occurs on main thread

### Phase 6: Move login plus bootstrap flow behind worker boundary

Preferred target:

1. login
2. verify OTP
3. unseal
4. derive client root share or equivalent bootstrap input in worker
5. hand bootstrap-ready data into session/bootstrap logic with minimal leakage

Two acceptable sub-phases:

1. intermediate step
   - worker returns derived bootstrap material if existing bootstrap path still requires it
2. target step
   - worker directly drives the OTP-specific bootstrap preparation path so main thread receives only final bootstrap outputs

Done criteria:

1. main thread no longer orchestrates login plus unlock plus bootstrap with secret-bearing intermediates
2. any temporary compatibility surface is explicitly marked and scheduled for removal

### Phase 7: Delete legacy main-thread OTP secret plumbing

1. remove direct main-thread `shamir3pass` Email OTP runtime usage
2. remove direct main-thread Email OTP derivation calls from runtime path
3. remove direct main-thread secret-bearing fetch assembly for OTP routes
4. collapse duplicate helper layers introduced only to bridge old and new designs
5. keep only public facades and non-secret orchestration on main thread

Done criteria:

1. no duplicate old/new OTP runtime paths remain
2. runtime path no longer depends on legacy string-backed secret plumbing

## Main-thread code that should shrink or disappear

The following current responsibilities should move out of main-thread OTP runtime code:

1. relayer fetch helper ownership for secret-bearing OTP routes
2. `shamir3pass` runtime ownership in Email OTP flow
3. `clientSecretB64u` handling after unseal
4. Email OTP HKDF derivation from recovered `S`
5. unlock challenge signing flow composition
6. enrollment sealing flow composition

The intended end state is that `client/src/core/TatchiPasskey/emailOtp.ts` becomes a facade file instead of the place where secret-bearing orchestration happens.

## WarmSessionManager boundary

`WarmSessionManager` should stay on the JS main thread.

### Reason

1. it is already the place where app-facing policy decisions live
2. it controls warm-session lifecycle and retention policy
3. its state is product/runtime coordination state, not cryptographic primitive state

### Rule

`WarmSessionManager` decides policy, but the worker runtime must enforce the cryptographic and secret-lifecycle side of the chosen policy.

That means:

1. main thread selects `session` vs `per_operation`
2. worker decides whether to retain or discard worker-owned secret-bearing runtime state according to the selected policy and server bounds

## Testing Plan

### Unit tests

1. worker request/response normalization
2. worker-owned fetch request formation
3. `email_otp_runtime` derivation vectors
4. zeroization of secret-bearing worker-owned buffers on success and error paths
5. OTP worker result surfaces do not expose raw recovered `S`

### Integration tests

1. `loginWithEmailOtpAndUnlockWallet` still returns expected public outputs
2. `loginWithEmailOtpAndBootstrapEcdsaCapability` still bootstraps correctly through worker path
3. `enrollEmailOtpWallet` still uploads canonical public verifier material
4. cookie and JWT session modes both work from worker-owned networking

### Cleanup and regression tests

1. no direct main-thread Email OTP runtime path still calls `getShamir3PassRuntime()`
2. no direct main-thread runtime path still calls Email OTP derivation helpers with recovered `S`
3. no worker result includes raw `clientSecretB64u`
4. stale worker-owned secret buffers are not reused across operations
5. `per_operation` mode discards worker-owned secret material immediately after final use

## Breaking Cleanup Requirements

This is a breaking refactor. We should remove old paths as we go.

Required cleanup rules:

1. do not keep a legacy main-thread OTP secret path around after worker path lands
2. do not keep duplicate helper layers that perform the same OTP runtime step in two places
3. do not preserve string-backed secret representations if byte-owned worker APIs are available
4. do not add feature flags for old vs new OTP runtime behavior

## Risks

1. worker-owned networking must be validated in all browser runtime environments we support
2. bootstrap integration may temporarily require an intermediate compatibility boundary
3. if downstream bootstrap code still requires base64url-derived secret material, we must treat that as temporary and close it promptly
4. error normalization must not accidentally surface sensitive internals from worker exceptions

## Acceptance Criteria

The refactor is complete when all of the following are true:

1. JS main thread only handles UI, routing, public API façade work, and `WarmSessionManager` policy decisions
2. Email OTP secret-bearing runtime flow executes inside a dedicated worker-owned runtime
3. `S` is decrypted only inside worker-owned runtime
4. Email OTP derivation no longer runs in main-thread JS runtime path
5. Email OTP networking for secret-bearing routes is worker-owned
6. direct main-thread `shamir3pass` runtime usage is removed from Email OTP flow
7. legacy main-thread OTP secret plumbing is deleted
8. tests cover zeroization, result-surface constraints, and worker-owned flow correctness

## Implementation Todo List

Completed:

1. write the OTP WASM-worker refactor plan
2. finish the prerequisite core Email OTP hardening that this refactor will build on

Remaining:

1. add `emailOtp` worker kind and transport plumbing
2. add worker-owned fetch helper for OTP routes
3. move `shamir3pass` Email OTP calls into OTP worker
4. add `wasm/email_otp_runtime`
5. move OTP derivation into `email_otp_runtime`
6. move unlock proof flow into OTP worker
7. move enrollment flow into OTP worker
8. move login plus bootstrap flow into OTP worker boundary
9. delete main-thread secret-bearing OTP orchestration
10. add focused worker, WASM, and integration tests

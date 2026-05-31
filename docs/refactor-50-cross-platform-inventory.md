# Refactor 50 Cross-Platform Boundary Inventory

Date recorded: 2026-05-27

## Browser Storage Boundaries

Direct IndexedDB construction is still concentrated in:

- `client/src/core/indexedDB/passkeyClientDB/manager.ts`
- `client/src/core/indexedDB/accountKeyMaterialDB/manager.ts`
- `client/src/core/indexedDB/seamsWalletDB/manager.ts`
- `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts`

The main signing-engine assembly leaks browser persistence through:

- `client/src/core/signingEngine/assembly/createPorts.ts`
- `client/src/core/signingEngine/assembly/createManagers.ts`
- `client/src/core/signingEngine/assembly/ports/*`
- `client/src/core/signingEngine/interfaces/runtime.ts`
- `client/src/core/signingEngine/interfaces/operationDeps.ts`
- `client/src/core/signingEngine/workerManager/SignerWorkerManager.ts`

Current extraction target: make `PlatformRuntime.storage` the assembly-facing
dependency, then move the legacy `UnifiedIndexedDBManager` behind the browser
adapter while `seams_wallet` repositories replace the old manager split.

## Browser Authenticator And UI Boundaries

Direct WebAuthn browser calls remain in:

- `client/src/core/signingEngine/webauthnAuth/fallbacks/safari-fallbacks.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts`

UI and worker construction remain browser-only in:

- `client/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workerTransport.ts`
- `client/src/core/signingEngine/workerManager/workers/shamir3pass/runtime.ts`

Current extraction target: route passkey create/get through
`AuthenticatorPort`, and keep Worker construction inside the browser
`SignerCryptoPort` adapter.

## Crypto And Signer Compute Boundaries

Portable signer work that should move behind `SignerCryptoPort` first:

- ECDSA HSS role-local client bootstrap in
  `client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- ECDSA bootstrap orchestration in
  `client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- Email OTP ECDSA role-local bootstrap inside
  `client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- Passkey PRF to ECDSA client-root derivation in
  `client/src/core/signingEngine/session/passkey/ecdsaClientRoot.ts`

Current extraction target: `prepareEcdsaClientBootstrap`, returning public facts,
relayer payload, and an opaque role-local state blob.

## Browser Runtime Globals

Runtime global usage that remains outside platform adapters:

- `crypto.subtle` in Email OTP worker derivation and passkey ECDSA client-root
  derivation.
- `localStorage` diagnostics in operation tracing and EVM-family event helpers.
- `window`, `document`, `MessagePort`, and `Worker` in wallet iframe host,
  confirmation UI, and worker transport.

Current extraction target: keep host/UI globals in browser entrypoints, and move
crypto/global signer operations behind `SignerCryptoPort` as each command is
coarsened.

## Rust/WASM Coverage

Existing Rust/WASM coverage already includes:

- NEAR signer WASM and worker.
- EVM signer WASM and worker.
- Tempo signer WASM and worker.
- HSS client signer WASM and worker.
- Email OTP worker runtime.
- Shamir 3-pass runtime.

The first native-platform seam should reuse those Rust/WASM command boundaries
rather than port TypeScript crypto helper composition.

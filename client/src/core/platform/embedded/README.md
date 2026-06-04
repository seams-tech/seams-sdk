# Embedded Platform Runtime

`EmbeddedPlatformRuntime` is the Linux/device adapter branch for running signing
flows without a browser container. It must implement the shared
`PlatformRuntime` contract with `kind: 'linux_embedded'` and keep web facade,
React, DOM, and wallet iframe concepts out of embedded packages.

## Required Ports

- `authenticator`: use FIDO2 hmac-secret, TPM-backed assertions, or another
  reviewed platform assertion source. The adapter must return normalized
  assertion records at this boundary.
- `secrets`: store long-lived local secrets in TPM, kernel keyring, libsecret,
  hardware secure element, or a reviewed platform secret provider. Raw secret
  bytes must have bounded lifetime in process memory.
- `signerCrypto`: call signer-core through a Rust crate, a C ABI, or an
  authenticated local daemon. Command payloads must use the shared signer-core
  command schemas from `client/src/core/platform/generated/`.
- `storage`: persist durable records in SQLite with transactions or atomic
  filesystem records with fsync-backed replace semantics.
- `http`: use TLS transport with explicit connect, write, read, and total
  request timeouts. Requests must bound body size and reject redirects unless the
  caller authorizes them.
- `clock` and `random`: use the OS monotonic clock for timeout measurement and
  the OS CSPRNG for random bytes.

## Replay And Resource Expectations

- Reuse signer-core conformance fixtures for every command supported by the
  embedded adapter.
- Add replay-vector coverage for local daemon transports, durable-record reloads,
  and power-loss recovery before shipping on hardware.
- Bound concurrent signer-core commands, durable-record write queues, HTTP
  retries, and in-memory pending operation state.
- Clear pending secret material on command failure, timeout, shutdown, and
  durable-record replacement.

## Exclusions

Embedded roots must not import:

- `client/src/web/SeamsWeb/**`;
- `client/src/core/WalletIframe/**`;
- `client/src/react/**`;
- `client/src/core/platform/browser/**`;
- DOM globals such as `window`, `document`, `navigator`, or `DOMException`;
- browser storage modules such as `IndexedDBManager` or
  `UnifiedIndexedDBManager`.

# Embedded Rust SDK Notes

The embedded SDK is a standalone Rust crate installed through Cargo. It should
own the `SeamsEmbedded` facade, device-local operation orchestration, and direct
Rust signer-core integration. It must not be implemented as a TypeScript npm
subpackage.

## Required Ports

- `authenticator`: use FIDO2 hmac-secret, TPM-backed assertions, or another
  reviewed platform assertion source. The adapter must return normalized
  assertion records at this boundary.
- `secrets`: store long-lived local secrets in TPM, kernel keyring, libsecret,
  hardware secure element, or a reviewed platform secret provider. Raw secret
  bytes must have bounded lifetime in process memory.
- `signerCrypto`: call signer-core through a Rust crate, a C ABI, or an
  authenticated local daemon. Command payloads must use signer-core schemas or
  language-neutral fixtures, not npm package exports.
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

Embedded Rust SDK code must not depend on npm `@seams/sdk` entry points for
runtime behavior. It must not mirror browser concepts such as:

- `client/src/web/SeamsWeb/**`;
- `client/src/web/SeamsWeb/walletIframe/**`;
- `client/src/react/**`;
- `client/src/core/platform/browser/**`;
- DOM globals such as `window`, `document`, `navigator`, or `DOMException`;
- browser storage modules such as `IndexedDBManager` or
  `UnifiedIndexedDBManager`.

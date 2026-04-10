# Export Spec

This document defines the intended export semantics for `ecdsa-hss`.

## Purpose

Export in `ecdsa-hss` means:

- disclose the canonical secp256k1 private key used by threshold signing

It does not mean:

- disclose a sidecar recovery key
- disclose a different deterministic key
- disclose backend-specific share state instead of the canonical key

## Canonical Export Object

The current working v1 export object is:

- canonical secp256k1 private scalar `x`

Export should therefore return:

- `x` as a 32-byte big-endian scalar
- enough public metadata to verify what key was exported

Recommended export metadata:

- compressed public key
- Ethereum address
- account identity and key version context

## Export Invariant

The exported object is correct only if:

- `pub(x)` equals the threshold signing public key
- `addr(pub(x))` equals the threshold signing address

So the export path must verify:

- exported private key public key equivalence
- exported private key address equivalence

before final delivery.

## Export Policy

Export must be:

- explicit
- user-confirmed
- operation-bound

The implementation must distinguish:

- non-export signing operations
- explicit export operations

Signing-only flows must not be able to request export-capable output by adding
an optional flag or reading leftover staged state.

## Non-Export Rule

The non-export rule is:

- `RegistrationBootstrap`, `SessionBootstrap`, and `NonExportSign` must not
  return canonical `x`
- those operations must not return any output equivalent to `x`

Only `ExplicitKeyExport` may return canonical `x`.

## Export Surface

The product boundary is now frozen at the policy level.

The working spec requires:

- a dedicated export operation type
- explicit user confirmation
- audit or telemetry distinction between signing and export

The export path must not be a hidden feature of:

- bootstrap
- sign
- recovery refresh

The crate-side v1 export boundary is:

- `export_evm_threshold_v1(...)`
- `export_from_respond_response_v1(...)`

Those entrypoints must reject non-export responses and must only succeed for
`ExplicitKeyExport`.

## Confirmation Requirements

v1 export confirmation is now frozen as:

- export must be initiated from a dedicated export UI action
- export must require an interactive user-confirmation step
- the confirmation step must be separate from normal signing confirmation
- the confirmation UI must identify:
  - account identity
  - target chain family: EVM / secp256k1
  - threshold public key or a stable preview of it
  - Ethereum address
- the confirmation UI must make clear that the threshold private key is being
  exported, not a sidecar recovery key

The implementation must not allow:

- piggybacking export on a signing confirmation
- hidden export through bootstrap or session refresh
- background export without an interactive confirmation boundary

## Audit And Telemetry Requirements

v1 export telemetry is also frozen at the product-policy level.

The product must emit an export-distinct audit or telemetry event that is
separate from normal signing.

Minimum required fields:

- event kind
- account identity
- device number or equivalent local device identifier when available
- scheme family: `secp256k1`
- operation kind: `ExplicitKeyExport`
- result: success or failure
- failure code when export is denied or fails
- timestamp

The telemetry surface must not contain:

- canonical `x`
- additive-share material
- backend threshold private shares
- raw root-share material

Structured logs are acceptable as the first implementation surface as long as
they obey the field and redaction rules above.

## Delivery Format

The exact wire/UI format is still open, but the semantic content is fixed:

- export returns canonical `x`
- not a backend share
- not a presign artifact
- not an unrelated recovery key

If the product later wraps `x` in an encrypted backup artifact, the artifact is
only valid if decrypting it yields the same canonical `x`.

## Export Safety Checks

Before the export result is accepted, the implementation should check:

1. exported `x` is a valid non-zero secp256k1 scalar
2. exported `x` derives the expected public key
3. exported `x` derives the expected Ethereum address
4. derived public key/address match the threshold-signing identity for that
   account

## Migration Rule

The `ecdsa-hss` export path is intended to replace the current separate
`prfSecond`-derived EVM export lane.

So once `ecdsa-hss` is fully integrated:

- export should disclose the threshold ECDSA key
- the sidecar export lane should be removed

The migration rule is now frozen as:

- there is no in-place migration from the old two-key EVM model to
  `ecdsa-hss`
- existing users must re-register to enter the one-key `ecdsa-hss` model
- `ecdsa-hss` accounts must never generate or consume `prfSecond`-derived EVM
  export artifacts
- old `prfSecond`-derived EVM export artifacts remain legacy-only and are not a
  valid export format for `ecdsa-hss`

That means:

- old accounts remain on the old model until re-registration
- new `ecdsa-hss` accounts use only the one-key export lane
- product cutover must remove the sidecar export lane from the new-account path
- until that canonical one-key export lane is live in product, new
  `ecdsa-hss` accounts must fail closed at the legacy export boundary and must
  never fall back to `prfSecond`

Current runtime status:

- the worker/export UI path accepts a canonical
  `ecdsa-hss-secp256k1-key-v1` artifact
- the public bootstrap/session activation APIs accept that same artifact shape
  so registration/login flows can thread it into active session state
- bootstrap carrying that artifact must classify the resulting key model as
  `ecdsa-hss-one-key-v1`
- registration and login warm-up flows may obtain that artifact only through an
  explicit product-side resolver seam; there is no implicit fallback producer
- if no resolver is installed, or if it returns `null`, runtime logs must make
  it explicit that the legacy product lane is still active
- product config may require one-key cutover for new EVM registrations via an
  explicit `thresholdEcdsaNewAccountKeyMode` setting
- when that setting requires `ecdsa-hss-one-key-v1`, registration must fail
  closed if the canonical artifact resolver does not return an artifact
- the remaining cutover task is sourcing that artifact from real `ecdsa-hss`
  account state instead of the old sidecar export flow
- active EVM session state may carry that artifact in memory only; the private
  key material must not be serialized into browser storage

## Related Docs

- Protocol shape:
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Integration shape:
  [integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)

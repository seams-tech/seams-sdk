# Export Spec

This document defines export semantics for the role-local `router-ab-ecdsa-derivation`
protocol.

## Purpose

Export lets the authorized client reconstruct the same secp256k1 private scalar
that threshold signing uses logically:

```text
x = x_client + x_relayer mod n
```

The server participates by releasing an explicit export share. The server never
computes or returns canonical `x`.

Excluded export meanings:

- a sidecar recovery key
- a different deterministic key
- a backend-specific threshold share artifact
- a presignature or online-signing session artifact

## Canonical Export Object

The canonical export object is:

- secp256k1 private scalar `x`

The client reconstructs it as:

```text
x_export = x_client + x_relayer_export mod n
```

The exported artifact delivered to wallet/import UI may contain:

- `x_export` as a 32-byte big-endian scalar
- compressed public key
- Ethereum address
- account identity and key version context
- export transcript metadata

The server-side export response may contain only:

- export-authorized `x_relayer_export`
- public transcript and authorization metadata

The export response must never contain:

- canonical `x`
- `privateKeyHex`
- `x_client`
- `y_client`
- `y_relayer`
- SigningWorker additive signing shares outside explicit export

## Export Invariant

The exported object is correct only if:

```text
x_export * G == X
ethereum_address(X) == expected_address
```

The client export runtime must verify:

- `x_export` is a valid non-zero secp256k1 scalar
- `x_export * G` equals the threshold signing public key
- `ethereum_address(x_export * G)` equals the threshold signing address
- the export transcript public identity matches the retained client public
  identity
- the export authorization binds to the same context and operation kind

## Export Policy

Export must be:

- explicit
- user-confirmed
- operation-bound
- transcript-bound
- auditable

The implementation must distinguish:

- non-export signing operations
- explicit export operations

Signing-only flows must reject export-capable output requests, optional export
flags, stale export envelopes, and leftover staged state.

## Export Authorization Freshness

Every explicit export request carries `export_request_nonce32` and an expiry.
The relayer stores used export nonces by:

```text
application_binding_digest
relayer_key_id
key_handle
threshold_session_id
export_request_nonce32
```

Freshness rules:

- nonce insertion must be atomic before relayer share release
- a nonce is consumed for success and for policy/digest failures that reach the
  relayer export endpoint
- a repeated nonce is rejected
- a crash after nonce insertion and before response delivery requires a fresh
  export request
- nonce records must live at least until `expires_at_unix_ms + clock_skew`
- first implementation should retain nonce records for at least 24 hours
- nonce storage must not contain secret share material

The authorization digest is binding evidence. It does not replace route/session
authentication, user confirmation, nonce replay checks, or policy checks.

## Non-Export Rule

The non-export rule is:

- `RegistrationBootstrap`, `SessionBootstrap`, and `NonExportSign` must not
  return canonical `x`
- those operations must not return `x_relayer` to the client
- those operations must not return any output that lets the client reconstruct
  `x`

Only `ExplicitKeyExport` may release `x_relayer_export` to the client, and the
client reconstructs `x` locally.

## Export Surface

The product boundary is frozen at the policy level.

The production export surface requires:

- a dedicated export operation type
- explicit user confirmation
- a transcript-bound export authorization witness
- audit or telemetry distinction between signing and export
- session cleanup that burns failed export state

The export path must be unreachable from:

- bootstrap
- sign
- recovery refresh
- non-export retry/abort cleanup

Existing crate export entrypoints must be replaced or constrained so they reject
non-export responses and accept only `ExplicitKeyExport` transcripts.

## Confirmation Requirements

Export confirmation requires:

- a dedicated export UI action
- an interactive user-confirmation step
- confirmation that is separate from normal signing confirmation
- visible account identity
- target chain family: EVM / secp256k1
- threshold public key or stable preview
- Ethereum address
- clear wording that the threshold private key will be reconstructed on the
  client

The implementation must reject:

- export piggybacked on a signing confirmation
- hidden export through bootstrap or session refresh
- background export without an interactive confirmation boundary
- export retries that reuse failed export session state

## Audit And Telemetry Requirements

The product must emit an export-distinct audit or telemetry event that is
separate from normal signing.

Minimum required fields:

- event kind
- account identity
- device number or equivalent local device identifier when available
- scheme family: `secp256k1`
- operation kind: `ExplicitKeyExport`
- public key or address fingerprint
- export authorization digest
- result: success or failure
- failure code when export is denied or fails
- timestamp
- expiration timestamp
- relayer key id
- nonce fingerprint

The telemetry surface must exclude:

- canonical `x`
- `x_client`
- `x_relayer`
- backend threshold private shares
- raw root-share material
- purpose-built triple or presign scalar material

Structured logs are acceptable as the first implementation surface if they obey
the field and redaction rules above.

## Delivery Format

The semantic export content is fixed:

- client-side output is canonical `x_export`
- server-side output is only the export-authorized relayer share envelope
- public metadata must be sufficient for client verification

If the product wraps `x_export` in an encrypted backup artifact, the artifact is
valid only if decrypting it yields the same scalar that verifies against `X`.

## Export Safety Checks

Before the export result is accepted, the implementation must check:

1. export authorization operation kind is `ExplicitKeyExport`
2. export authorization public identity matches the retained client identity
3. export authorization context binding matches the retained client context
4. server export envelope transcript matches the authorization transcript
5. reconstructed `x_export` is a valid non-zero secp256k1 scalar
6. `x_export * G == X`
7. `ethereum_address(X) == expected_address`
8. export nonce has not been used
9. relayer key id matches the retained relayer state
10. authorization is within its validity window

Failed checks must burn the export session and any received export share. Retry
must start from a fresh explicit export session.

## Relayer Key Rotation

Export is bound to the retained `relayer_key_id`. If the request, authorization,
or persisted relayer state disagree on `relayer_key_id`, the export must fail.

Initial rotation policy:

- relayer key rotation requires new role-local Router A/B ECDSA derivation bootstrap
- existing export authorizations become invalid after rotation
- existing presign/triple state becomes invalid after rotation
- old relayer-key identifiers remain in audit records only

## Migration Rule

The `router-ab-ecdsa-derivation` export path replaces the separate `prfSecond`-derived EVM export
lane.

Cutover rules:

- new `router-ab-ecdsa-derivation` accounts use only the role-local one-key export lane
- existing accounts must re-register to enter the `router-ab-ecdsa-derivation` one-key model
- `router-ab-ecdsa-derivation` accounts must never generate or consume `prfSecond`-derived EVM
  export artifacts
- product cutover must remove the sidecar export lane from the new-account path
- until role-local export is live in product, new `router-ab-ecdsa-derivation` accounts must
  fail closed at the old export boundary

Active EVM session state may carry the reconstructed export artifact in memory
only during the explicit export flow. Private key material must not be serialized
into browser storage.

## Related Docs

- Protocol shape:
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/protocol.md)
- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/security.md)
- Integration shape:
  [integration-purpose-built-ecdsa.md](integration-purpose-built-ecdsa.md)

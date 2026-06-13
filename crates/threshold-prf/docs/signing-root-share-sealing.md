# Signing Root Share Sealing

Last updated: June 13, 2026

## Scope

The threshold-prf Rust crate does not define storage, KMS, HSM, TEE, or
database behavior. Signing-root share sealing is a server SDK persistence
boundary for encrypted share bytes.

The active threshold-prf derivation API expects signing-root share wires:

```text
u16be(share_id) || canonical_scalar(share_i)[32]
```

total length: 34 bytes.

## Active The canonical API Resolver Boundary

The server SDK active resolver shape is policy-aware:

- storage lists sealed share records by signing root id/version
- a decrypt adapter returns plaintext share-wire bytes
- the resolver parses the plaintext with the threshold-prf WASM parser
- the resolver selects exactly `threshold` distinct shares from the configured
  policy
- scratch plaintext buffers are zeroized after parsing

The resolver types are:

- `SigningRootShareResolver`
- `SealedSigningRootShare`
- `SigningRootShareSource`
- `SigningRootShareDecryptAdapter`

## Retained SDK Persistence Envelope

The server SDK still contains a `tprs || 0x01` AES-GCM envelope for existing
sealed signing-root records:

```text
magic[5] || nonce[12] || aes_gcm_ciphertext_and_tag
```

where:

- `magic = 0x74 0x70 0x72 0x73 0x01`
- `nonce` is a fresh 96-bit AES-GCM nonce from WebCrypto `getRandomValues`
- the AEAD tag is the WebCrypto AES-GCM default 128-bit tag
- KEK material is AES-256-GCM only

This retained envelope is a persistence format. It is not a core
threshold-prf protocol version and should not be used as a reason to reintroduce
fixed-pair threshold-prf APIs.

## AAD

The AES-GCM additional authenticated data is public metadata encoded as:

```text
u16be(len(domain))              || domain
u16be(len(signing_root_id))     || signing_root_id
u16be(len(signing_root_version))|| signing_root_version
u8(share_id)
u16be(len(kek_id))              || kek_id
```

with:

- `domain = "seams/signing-root-share/aes-gcm/v1"`
- `signing_root_id` trimmed and non-empty
- `signing_root_version` trimmed, or empty bytes when absent
- `kek_id` trimmed and non-empty

Opening a sealed share with different signing root id, signing root version,
share id, or KEK id must fail before plaintext is accepted.

## Cleanup Direction

Future storage migrations should move persisted plaintext shape to 34-byte
share wires and expose that only through the resolver/decrypt adapter
boundary. Compatibility code belongs at persistence import/export boundaries.

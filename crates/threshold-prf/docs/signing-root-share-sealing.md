# Signing Root Share Sealing

This document freezes the server SDK v1 sealed-share format used before
`SigningRootShareWireV1` bytes enter the threshold-prf derivation boundary.

The threshold-prf Rust crate does not define storage, KMS, HSM, TEE, or
database behavior. This format is a server SDK envelope for storing encrypted
signing-root share wires and feeding the SDK `SigningRootShareResolver`.

## Envelope V1

`sealed_signing_root_share_v1` is:

```text
magic[5] || nonce[12] || aes_gcm_ciphertext_and_tag
```

where:

- `magic = 0x74 0x70 0x72 0x73 0x01`, the ASCII string `tprs` plus version
  byte `1`
- `nonce` is a fresh 96-bit AES-GCM nonce from WebCrypto `getRandomValues`
- plaintext is exactly one decrypted `SigningRootShareWireV1`
- the AEAD tag is the WebCrypto AES-GCM default 128-bit tag
- KEK material is AES-256-GCM only

The encrypted plaintext remains the fixed-width secret wire:

```text
u8(share_id) || canonical_scalar(share_i)[32]
```

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
- `share_id` exactly `1`, `2`, or `3`
- `kek_id` trimmed and non-empty

Opening a sealed share with a different signing root id, signing root version,
share id, or KEK id must fail before the plaintext wire is accepted.

## Boundary Rules

- Store implementations persist only `sealedShare` bytes plus public metadata.
- Decrypt adapters return plaintext bytes only to
  `resolveSigningRootShareWirePair`; that resolver copies validated wires and
  zeroizes adapter scratch buffers.
- The server SDK host parser validates fixed width and share-id consistency.
  Canonical scalar validation remains in the Rust/WASM threshold-prf parser.
- The raw KEK helper is for SDK integration and self-hosted deployments. A
  production SaaS deployment should resolve KEKs through KMS, HSM, or an
  equivalent non-exportable key boundary.

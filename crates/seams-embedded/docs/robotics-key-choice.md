# Embedded Robotics Key Choice

This note records the current split-key recommendation for embedded robotics
signers.

## Recommendation

Use Router A/B ECDSA derivation when the product can use a secp256k1/EVM-family key. Use the
Router A/B Streaming Yao lifecycle when standard Ed25519 seed compatibility,
NEAR-native account compatibility, or another Ed25519-only integration is
required.

## Router A/B ECDSA Derivation

Router A/B ECDSA derivation uses role-local additive key material:

```text
x_client = H_scalar("client-share", context, y_client)
x_relayer = H_scalar("relayer-share", context, y_relayer)
x = x_client + x_relayer mod n
X = x_clientG + x_relayerG
```

The device derives and retains its client share. The relayer derives and
retains its own share. The shared public key follows from public elliptic-curve
addition. Client-side work is limited to hash-to-scalar, a secp256k1 scalar
multiplication, public transcript checks, and threshold signing.

## Ed25519 Streaming Yao

Standard Ed25519 derives its signing scalar and deterministic nonce prefix from
a 32-byte seed:

```text
h = SHA512(seed)
a = clamp(h[0..32])
prefix = h[32..64]
A = aB
```

Router A/B evaluates the fixed SHA-512-and-clamp circuit between Deriver A and
Deriver B. The large garbled stream remains between those services. The device
sends compact role inputs, receives its recipient package, verifies the public
relation, and retains only its active FROST share. Ordinary signing performs no
Yao evaluation.

Registration, recovery, refresh, and authorized seed export carry the Yao
latency and service-compute cost. This cost belongs to the independently
operated Derivers rather than the embedded client. Local evidence and exact
wire counts are recorded in `docs/yaos-ab.md`; deployed latency remains a
separate release gate.

## Security Posture

Both protocols require strict role separation, authenticated requests,
artifact/version binding, replay protection, recipient encryption, and
constant-time review. Production Ed25519 uses independently administered
Deriver A and B deployments. Same-account deployment is limited to development
and staging because it does not establish independent administration.

The device never receives the server share during normal signing. The server
roles never receive the device share or the reconstructed Ed25519 seed.
Explicit export is a distinct policy-authorized lifecycle whose seed is
reconstructed only at the Client boundary.

## Device Design

The embedded signer should:

- keep its selected auth root and active signing share in the device secret
  store;
- verify public identity, epoch, transcript, and recipient bindings;
- reject runtime protocol/profile negotiation;
- use ordinary threshold signing after activation;
- discard retired shares after recovery or refresh; and
- expose seed export only through the explicit authorized Ed25519 Yao flow.

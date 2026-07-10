# Independent Ed25519 Yao Vector Verifier

This directory contains a Python 3 standard-library implementation of the
Ed25519 Yao v1 clear arithmetic. It imports no Rust package, generated module,
workspace JavaScript dependency, or third-party Python package.

The verifier accepts any nonempty, strictly shaped v1 corpus. It independently
checks stable-context encoding and binding, split seed and scalar arithmetic,
SHA-512 and RFC 8032 clamping, scalar reduction, Edwards25519 base-point
multiplication and compression, public keys, and the export-only seed result.

Run it from the repository root:

```sh
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  tools/ed25519-yao-generator/vectors/ed25519-yao-kdf-v1.json
python3 tools/ed25519-yao-verifier/verify_vectors.py \
  /tmp/ed25519-yao-differential-v1.json \
  --differential-seed-hex \
  5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
python3 -m unittest discover \
  -s tools/ed25519-yao-verifier -p 'test_*.py'
```

The optional differential seed makes the verifier independently regenerate
the SHA-512-expanded inputs, scalar reductions, context digest, participant
identifiers, request-kind cycle, and exact case identifier for each index.
Schema auto-detection also verifies the KDF continuity corpus with a standalone
application-binding encoder, SHA-256 digest, HMAC/HKDF-SHA256 implementation,
frozen role/source/output tags, all eight contributions, and the complete
joined Ed25519 trace. It checks that the four immutable binding facts produce
the digest consumed by the stable context before reproducing the KDF. The
binding facts are wallet identity, Ed25519 signing-key identity, logical
signing-root identity, and the immutable positive key-creation signer slot. It
independently enforces the version-one identifier grammar of one or more visible
ASCII bytes in `0x21..=0x7e`.

All inputs are committed or generated public test vectors. The arithmetic is
variable-time Python intended solely for host-side verification. Production
protocol code and secret material must never depend on this directory.

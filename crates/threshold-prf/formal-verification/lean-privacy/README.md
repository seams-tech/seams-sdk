# `threshold-prf` Lean Privacy Track

This track contains the narrow structural Lean privacy model for
`threshold-prf` one-server and two-server execution-state visibility.

The model distinguishes:

- one-server mode, where one signer observes two plaintext root shares and can
  reconstruct `k_org`
- two-server mode, where each server observes only one plaintext root share
- combiner state, which should observe partials and `y_relayer`, not plaintext
  root or share scalars

Implemented proof surface:

- one-server mode observes enough shares to reconstruct `k_org`
- one two-server participant state does not contain enough material to
  reconstruct `k_org`
- combiner state excludes plaintext root and share scalars
- public output state excludes root scalars, share scalars, and reconstructed
  `k_org`

Do not claim malicious-runtime privacy for one-server mode.

This track does not prove runtime isolation, transport confidentiality,
side-channel resistance, or malicious remote partial correctness without DLEQ,
TEE attestation, or an equivalent mechanism.

Run it with:

```bash
just threshold-prf-fv-privacy
```

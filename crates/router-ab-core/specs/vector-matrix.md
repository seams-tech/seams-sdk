# Vector Matrix

This spec defines the committed vector corpus required before candidate
selection and production implementation.

## Directory Layout

Recommended layout:

```text
fixtures/
  context/
    context-v1.json
    transcript-v1.json
  envelopes/
    envelope-aad-v1.json
    package-commitment-v1.json
  minimum-level-c/
    evidence-accept-v1.json
    evidence-reject-v1.json
  candidates/
    mpc-threshold-prf-v1.json
    split-root-v1.json
  refresh/
    refresh-context-v1.json
    activation-v1.json
  diagnostics/
    error-redaction-v1.json
```

The initial committed fixture now includes context and transcript digests. The
additional suite files above should split the corpus by protocol surface as the
candidate algorithms land.

## Determinism

Vectors use deterministic test inputs. Random-looking bytes must be generated
from named seeds:

```text
seed = "router-ab-derivation/<suite>/<case-id>"
bytes = SHA-256(lp(seed) || lp(counter))
```

Production code must use cryptographic randomness where required. Vector
determinism is only for reproducible tests.

## Context And Transcript Vectors

Required cases:

- valid registration context
- valid export context
- valid refresh context
- changed candidate id changes digest
- changed request kind changes digest
- changed correctness level changes digest
- changed account scope changes digest
- changed root epoch changes digest
- changed ceremony id changes digest
- changed role identity changes digest
- changed signer-set id changes digest
- changed signer index changes digest
- changed signer key epoch changes digest
- changed quorum policy changes digest
- changed selected relayer identity changes digest
- changed client identity changes digest
- changed client ephemeral public key changes digest
- empty required field rejection
- non-`all(2)` quorum rejection
- unknown version rejection

## Envelope Vectors

Required cases:

- valid Router-to-A signer input AAD
- valid Router-to-B signer input AAD
- valid A-to-client package commitment
- valid B-to-client package commitment
- valid A-to-relayer package commitment
- valid B-to-relayer package commitment
- recipient mismatch rejection
- content kind mismatch rejection
- same idempotency key with same ciphertext digest acceptance
- same idempotency key with different ciphertext digest rejection

## Minimum Level C Vectors

Required acceptance cases:

- valid registration evidence
- valid export evidence
- valid refresh evidence before activation

Required rejection cases:

- duplicate Signer A/B identity
- Signer A receipt under Signer B identity
- Signer B receipt under Signer A identity
- root epoch mismatch
- transcript mismatch
- recipient mismatch
- replay mismatch
- unauthenticated receipt
- package commitment mismatch

## Candidate Vectors

Before candidate algorithms land, the corpus pins decision-gate vectors for
each candidate and request kind. Those vectors assert the current
`not_implemented` boundary and bind the context and transcript digests that the
future output vectors must preserve.

For each candidate:

- registration output share generation
- export output share generation
- refresh output share generation or explicit unsupported-refresh vector
- malformed signer input
- malformed recipient package
- signer identity mismatch
- epoch mismatch
- candidate-specific proof acceptance
- candidate-specific proof rejection

## Diagnostic Vectors

Every diagnostic vector asserts:

- stable error code
- redacted diagnostic object
- no forbidden plaintext substrings
- no secret byte dumps

## Formal Verification Anti-Drift

Proof crates should load a reduced vector subset:

- context field order
- transcript field order
- role/output authorization
- replay mismatch
- Minimum Level C evidence binding

The proof inventory must name every vector family it depends on.

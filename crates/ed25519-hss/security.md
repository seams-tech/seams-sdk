# Security Model

This file is the security-focused entrypoint for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).
Protocol shape and message details live in
[specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md).

## Threat Model

Two parties jointly derive Ed25519 signing-share material:

- client:
  derives `y_client` and `tau_client`
- server:
  derives `y_relayer` and `tau_relayer`

The goal is to preserve the hidden seed path and durable-share projection
without either side learning the other side's root material.

The current security claims are for:

- passive/semi-honest cryptographic execution
- hardened client/server runtime boundaries for the deployed staged flow

This crate does not yet claim full malicious security.

## Core Security Goals

The fixed hidden computation is:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`

The intended security properties are:

- neither party learns plaintext `d`
- neither party learns plaintext `a`
- the client learns only `x_client_base` plus public verification data
- the server learns only `x_relayer_base` plus public verification data

Reconstruction identity:

- `a = 2 * x_client_base - x_relayer_base mod l`

## Current Boundary Status

For non-export production flows, the hardened boundary requirement is:

- the client must not be able to reconstruct per-account `y_relayer`
- the client must not be able to reconstruct per-account `tau_relayer`

The old joined-input sealed packet seam did not satisfy that stronger product
goal and now survives only as regression-test support.

The current kept production design is the staged server-assisted flow:

- `ServerAssistInit` authenticates the init/handle handoff
- add-stage is the first real online execution step
- after add-stage, raw relayer roots are dropped
- later stages advance from server-owned continuation state

That staged continuation model now works like this:

- add-stage executes only add-stage and stores the first message-schedule
  continuation plus accepted minimal retained `projector_inputs`
- each `message_schedule(n)` response advances only the immediately prior
  schedule continuation
- each `round_core(n)` response advances only the immediately prior round-core
  continuation
- `output_projection` materializes final output only when that stage executes

The accepted retained-state exception after add-stage is:

- `projector_inputs`

Those projector prerequisites are:

- server-owned only
- not client-visible
- not final output bundles
- kept only because delaying them further would require recomputation from
  relayer roots that have already been dropped

## ExplicitKeyExport Exception

`ExplicitKeyExport` is the intentional exception to the non-export secrecy
rule.

Why:

- export is the one flow where the user is explicitly asking to receive
  private-key-equivalent material in the client runtime
- a compromised browser/app runtime can therefore abuse or exfiltrate that
  material by design

So the stronger secrecy guarantee is scoped as:

- non-export flows:
  client must not be able to reconstruct `y_relayer` or `tau_relayer`
- `ExplicitKeyExport`:
  client intentionally receives key-equivalent material, so that stronger
  claim does not apply

Safer future directions if export ever needs a stronger client boundary:

- encrypted backup export:
  export a sealed backup artifact instead of the raw canonical seed, but only
  if the decrypting key lives outside the page/runtime being protected
- device-to-device migration export:
  move key-equivalent material into another trusted device or stronger runtime
  boundary instead of disclosing it to normal browser-page code

## Factors Required For Full Key Recovery

Reconstructing the signing key still requires all of:

- `y_client`
- `y_relayer`
- the correlated hidden computation that produces the final projected shares

Blast radius is also contained by context binding:

- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- `credentialId`

That means one account or credential compromise does not automatically expose
another.

## Current Security Level

Current security posture:

- passive/semi-honest cryptographic model
- production boundary hardened so non-export flows do not expose reconstructable
  relayer roots to the client

Not yet claimed:

- full malicious security
- complete active verification of all garbler behavior

The broader malicious-security roadmap lives in
[docs/plans/malicious-security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/malicious-security.md).

## Assumptions

- DDH hardness on Curve25519
- ChaCha20Poly1305 AEAD security
- HKDF behaves as a strong pseudorandom extractor
- WebAuthn PRF output is unpredictable and bound to the credential

## Related Docs

- Protocol and wire shape:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)
- Derivation details:
  [specs/derivation.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/derivation.md)
- API/runtime overview:
  [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)

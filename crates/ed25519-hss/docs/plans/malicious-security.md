# Optional Future Hardening

This note is an optional future-work roadmap for
[crates/ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

It is not required to understand the current implementation. The current
runtime shape, protocol behavior, and security boundary are described in:

- [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)

## Current Status

Refactor 3 and Refactor 4 already landed the important boundary correction:

- the old sealed `ServerInputsPacket` production seam is gone
- non-export production flows no longer expose reconstructable
  `y_relayer` or `tau_relayer` to the client
- the staged server-assisted flow now advances through real server-owned
  continuation state from add-stage onward

That fixes the specific production boundary bug.

What is still not claimed:

- full malicious-client security
- malicious-secure OT
- authenticated Beaver protections
- full active-security verification across the protocol

## Why This File Still Exists

This file is only for the next hardening tier:

- stronger abuse resistance for authenticated malicious clients
- eventual groundwork for a credible malicious-security claim

The realistic attack shape is repeated probing, not one-shot exfiltration:

- replay and cross-session mixing
- malformed or selectively inconsistent requests
- adaptive retries across many runs
- studying abort behavior, timing classes, and acceptance differences

## Tier 1: Practical Abuse Resistance

This tier is optional product hardening, not a formal malicious-security
claim.

Recommended controls:

- one-time-use prepared sessions
- replay rejection
- strict transcript/session binding
- minimal client-visible failure detail
- verify-before-reveal output discipline
- rate limiting per account, credential, and source
- anomaly detection for malformed threshold-eval traffic

This is the pragmatic next step if the concern is authenticated abuse rather
than formal active-security proofs.

## Tier 2: Stronger Cryptographic Hardening

This tier is the future path if a real malicious-client claim is required.

Needed work:

- malicious-secure OT
- authenticated Beaver usage
- stronger transcript binding across all setup and online artifacts
- adversarial tests aimed at cheating-client behavior
- proof-oriented review of what is and is not released before abort

This is a separate workstream from the Refactor 3/4 boundary fix and should be
evaluated against latency and deployment cost.

## Explicit Non-Goal

This note does not reopen the `ExplicitKeyExport` exception.

If export ever needs a stronger client boundary, that should be handled as a
different product design, such as:

- encrypted backup export
- device-to-device migration export

Those directions are documented in
[security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md).

---
title: Blind Deterministic Key Derivation
---

# Blind Deterministic Key Derivation

Router A/B with Streaming Yao is a key-ceremony architecture: a blind,
deterministic, two-party key-derivation ceremony that feeds a threshold wallet.
The wallet key is born shared. The seed and private scalar exist only as
shares, on every machine, at every point in the lifecycle — yet the key remains
recoverable and exportable from durable roots.

One sentence version:

> A 2-of-2 threshold Ed25519 wallet whose deterministic, RFC 8032-compatible
> key derivation runs inside a garbled-circuit 2PC between two mutually
> distrusting, independently administered blind Derivers — so no machine ever
> holds the joined seed or private key, while the key stays exportable and
> recoverable from durable roots.

## The Layered Model

The architecture is three cryptographic layers plus one crypto-free
orchestration layer:

| Layer | Mechanism | Role |
| --- | --- | --- |
| Custody | Additive secret sharing | The seed is defined as the sum of client and server contributions derived from durable roots. It is never assembled. Linear operations — share addition, blinding, refresh deltas — happen locally on shares with no interaction. |
| Derivation | Fixed-function Yao 2PC | The single non-linear step (`SHA-512 -> clamp -> mod l`) is evaluated jointly by Deriver A and Deriver B on their shares. This step is forced by RFC 8032 export parity; it is the only reason a garbled circuit exists. |
| Signing | 2-of-2 threshold signing | Outputs land as blinded scalar shares held by the client and the SigningWorker. All normal signing is client plus SigningWorker; Derivers never appear in the hot path. |
| Orchestration | Router | Admission, authorization, replay protection, and envelope relay. Router carries only ciphertext, public metadata, and signed receipts. |

The distinctive structural move: the parties that compute the key (Derivers A
and B) are disjoint from the parties that hold the key (client and
SigningWorker). The compute parties are ephemeral and blind — protocol-generated
random output sharing means even the machines that evaluate the derivation
never see what they derived.

## How This Differs From Conventional Threshold Signers

Ordinary threshold-wallet key generation runs an interactive DKG between the
eventual key holders and samples a random, unrecoverable key. This architecture
replaces that with a derivation ceremony that has three properties conventional
designs give up:

### Nobody-blind key export and recovery

The key is deterministic from committed roots, so recovery preserves the
registered public key exactly, and the seed is exportable bit-for-bit as a
standard RFC 8032 Ed25519 seed. During an explicitly authorized export, the
Derivers produce masked seed shares encrypted only to the authorized client;
the client combines them, recomputes the public key, and verifies it against
the registered identity. No server role — Router, Deriver A, Deriver B, or
SigningWorker — sees the seed at any point, including during export. A
DKG-based wallet has no seed to export; schemes that reconstruct keys
server-side for export break the custody model at exactly the moment it
matters most.

### Serverless deployment

The whole ceremony fits serverless limits. The client and Router exchange
compact envelopes measured in KiB; the multi-MiB garbled-circuit stream travels
directly between Deriver A and Deriver B with bounded memory. All roles deploy
as Cloudflare Workers with Durable Object state — no server fleet, near-zero
idle cost, and a same-account development profile that scales up to the
separate-account production topology without protocol changes. See
[Serverless Threshold Signing](/concepts/threshold-signing/serverless-threshold-signing).

### No TEE requirement

The confidentiality and correctness claims come from cryptography (the 2PC
protocol, one-use tickets, authenticated transcripts) and from administrative
separation (independently operated A and B accounts) — not from hardware
attestation. There is no enclave in the trust model, so there is no attestation
supply chain to trust and no enclave side-channel class to carry. The same
protocol therefore runs on any runtime that can host the roles — Workers,
containers, or plain VMs — provided the deployment reproduces the same
administrative separation and release controls. TEEs remain available as
optional defense-in-depth around the same protocol shape, not as a
prerequisite.

## Trust Boundaries

The production target is privacy and correctness-with-abort against the Router
plus at most one malicious Deriver:

- no single party — including the client, outside an authorized export — ever
  learns the joined seed or private scalar;
- Deriver A and Deriver B each see only their own role-local inputs and an
  output share that is useless alone;
- Router sees ciphertext, public metadata, and signed receipts;
- the client and SigningWorker hold blinded scalar shares whose combination is
  the intended 2-of-2 threshold boundary.

The claim excludes A+B collusion, client-plus-SigningWorker collusion (that is
the designed threshold boundary, not a failure), platform-wide compromise of
the hosting provider, and fairness or guaranteed output delivery.

## Status

Streaming Yao is the approved Ed25519 lifecycle protocol and an implementation
target under active development. Production remains gated on a reviewed
actively secure construction, malicious-secure OT, input provenance,
authenticated private outputs, separate-account deployment, constant-time
review, and independent security review.

Read next:

- [Router A/B](/concepts/threshold-signing/router-ab)
- [Streaming Yao A/B](/concepts/threshold-signing/streaming-yao-ab)
- [Recovery and Export](/concepts/custody/recovery-and-export)

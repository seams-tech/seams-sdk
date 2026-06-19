# TEEs vs Serverless MPC

Date updated: June 12, 2026

## Summary

TEE-based signing and serverless MPC optimize for different things.

TEE signing can minimize single-signature latency by reconstructing or using key
material inside an enclave. Serverless MPC optimizes deployability: it can run on
commodity serverless platforms such as Cloudflare Workers without specialized
enclave infrastructure.

Our product direction favors:

> simple serverless self-hosted MPC

This keeps hosting and self-hosting simple, while reducing latency through warm
signing sessions, presign pools, batching, and route/state optimization.

Router A/B makes this less binary than a plain "TEE vs serverless MPC" choice.
The default self-host profile can stay HSS/serverless-first, while a hardened
profile can run Signer A and Signer B inside attested TEEs and use a non-HSS
threshold signer where the TEE boundary supplies the tamper-resistance
assumption. That profile is a paid enterprise hardening path rather than the
baseline self-host requirement.

## Trust Model

### TEE Recombine-And-Sign

In a recombine-and-sign TEE model, key shares are released into an enclave, the
enclave reconstructs or effectively uses the full signing key, and the enclave
produces a normal signature.

This can be fast, but the enclave service becomes the signing trust root.

Without user-verifiable public attestation, a TEE wallet mostly asks users to
trust the operator:

- users cannot verify the exact enclave binary that handles key material
- users cannot verify upgrade policy or deployment controls
- users depend on the operator's attestation and secret-release policy
- deployment authority becomes security-critical

A stronger TEE design needs:

- public or relying-party-verifiable attestation
- allowlisted enclave measurements
- constrained and transparent upgrade policy
- strict key-release rules
- auditable deployment controls

Even then, the operator controls the enclave service and can usually stop,
gate, upgrade, or route signing. That makes many TEE wallets operator-custodial
or semi-custodial from a practical control perspective.

### Serverless MPC

In serverless MPC, signing authority stays split across parties. No ordinary
serverless process needs to reconstruct the full private key during normal
operation.

The tradeoff is protocol latency:

- Ed25519/FROST signing needs online nonce and signature-share coordination
- ECDSA threshold signing is heavier unless presignatures are available
- route, storage, and worker overhead matter

The advantage is deployment simplicity:

- no enclave hardware
- no attestation service
- no enclave image measurement workflow
- no special key-release infrastructure
- no TEE-specific regional constraints

## Latency

TEE recombine-and-sign usually wins on single-signature latency. Once key shares
are inside the enclave, signing is ordinary Ed25519 or ECDSA signing.

Serverless MPC has extra protocol work. For Router A/B Ed25519 normal signing,
the pool-miss path uses a public prepare request followed by finalize, while the
pool-hit path uses one public finalize request:

1. Pool miss: Router A/B prepare creates a single-use server nonce handle, then
   Router A/B finalize consumes the exact bound handle.
2. Pool hit: the client consumes a prefilled Router A/B presign entry and sends
   one finalize request after user confirmation.

That narrows the latency gap while preserving the serverless MPC deployment
model.

## Hosting Cost

TEE recombine-and-sign usually shifts cost into specialized always-on
infrastructure:

- TEE-capable instances are a narrower and often more expensive class of compute
- production redundancy usually requires multiple enclave-capable instances
  across zones or regions
- autoscaling is less elastic than Workers-style serverless
- provisioning includes enclave image builds, measurements, attestation setup,
  deployment signing, and secret-release policy
- incident recovery requires replacement hosts to be provisioned, measured,
  attested, and trusted before they receive shares
- regional availability depends on where the cloud provider supports the TEE
  product

Cloudflare Workers-style serverless MPC has a simpler cost model:

- request-based compute
- commodity serverless deployment
- broad horizontal scaling
- less always-on infrastructure
- simpler self-hosting story for teams that already deploy serverless workloads

TEE costs vary by provider and workload, so this is an operational tendency
rather than a universal rule. The practical point is that TEE redundancy and
attestation operations are materially heavier than ordinary serverless hosting.

## Availability And Operations

TEE operations are more specialized:

- replacement capacity must be enclave-capable
- new instances must pass attestation and policy checks
- secret release must be controlled and audited
- upgrades require measurement and policy changes
- downtime recovery can be slower because provisioning is security-sensitive

Serverless MPC operations are simpler:

- stateless routes can scale horizontally
- short-lived protocol state can live in shared storage or Durable Objects
- regional deployment follows ordinary serverless patterns
- recovery does not require enclave-specific provisioning

The serverless model can still have bottlenecks. Storage, Durable Objects,
rate-limiters, session records, and nonce/presign pools must be designed for
concurrency. Those are ordinary distributed-systems problems rather than
TEE-specific operations.

## Product Positioning

TEE signing can be faster per signature. Serverless MPC is easier to deploy and
self-host.

Use this framing:

> TEEs can reduce signing latency, but they add specialized infrastructure,
> attestation operations, and an operator-controlled enclave trust root. Our
> design favors deployability: simple serverless self-hosted MPC that runs on
> commodity platforms like Cloudflare Workers, with latency reduced through warm
> sessions and presign pools.

Avoid overstating the comparison:

- TEE systems can be well engineered.
- TEE systems can scale with enough operational investment.
- Serverless MPC still needs careful protocol-state and storage design.

The defensible claim is:

> A TEE recombine-and-sign model can be faster per signature, while serverless
> MPC trades some latency for simpler, cheaper, more elastic self-hosting without
> specialized enclave infrastructure.

## Decision

For this project, the preferred baseline architecture is serverless Router A/B
with HSS where server-blindness is required without trusted hardware.

Reasons:

- Cloudflare Workers compatibility is a core deployment goal.
- Self-hosting should not require TEE hardware or managed enclave services.
- The system is not designed for permissionless infrastructure.
- The latency gap can be reduced with warm sessions, Ed25519 presign pools,
  ECDSA presignatures, batching, and dispatch-path optimization.
- The product narrative is stronger when customers can deploy the signer as
  ordinary serverless infrastructure.

TEE-backed Router A/B remains a valid hardened profile:

- Signer A and Signer B can run inside attested TEEs.
- A non-HSS threshold signer can reduce bootstrap or signing latency where the
  TEE trust model is accepted.
- The Router A/B protocol surface, migration story, deployment manifest, and
  client SDK behavior should remain stable.
- Attestation, secret-release policy, enclave upgrades, and provider operations
  become explicit enterprise controls.

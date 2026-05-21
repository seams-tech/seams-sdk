# Branding

## Core Positioning

Simple serverless self-hosted MPC.

## Supporting Line

Deploy threshold signing infrastructure on commodity serverless platforms
without HSMs, TEEs, custom validator infrastructure, or specialized operators.

## Longer Positioning

This project is for teams that want threshold signing and recoverable key
infrastructure without operating a custom cryptography cluster. The system is
designed to run in normal application infrastructure, including Cloudflare
Workers, while keeping client and server signing material separated by protocol
boundaries.

## Protocol Rationale

The system augments threshold ECDSA-style custody with an exportable-key path.
That exportability is why the HSS protocols matter: they let the client and
server derive signing material through a server-blind key-generation flow,
instead of requiring the server to learn the client's exportable signing share
during normal protocol execution.

In technical docs, describe that mechanism as homomorphic hidden evaluation.
HSS lets the parties derive exportable signing shares over shared inputs, so the
server can participate in key generation without receiving the client's final
share through the normal protocol boundary.

## Deployment Scope

This MPC design is for application-controlled or self-hosted infrastructure. It
is not designed for permissionless validator sets, open-membership consensus,
or adversarial public networks where unknown operators can join the signing
committee.

## Claim Guardrails

Use:

- simple serverless self-hosted MPC
- serverless MPC you can self-host
- threshold signing for normal serverless infrastructure
- deployable without HSMs or TEEs

Avoid:

- fully malicious-secure MPC
- enclave-backed MPC
- server-memory compromise resistant
- no-trust server security
- permissionless MPC
- validator-network MPC

Those stronger claims require protocol work beyond the current deployment
model, such as Level B executor-memory safety or full malicious-security
hardening.

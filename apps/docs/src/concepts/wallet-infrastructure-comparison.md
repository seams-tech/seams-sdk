---
title: Wallet Infrastructure Comparison
---

# Wallet Infrastructure Comparison

Wallet infrastructure choices differ on control, cost shape, deployment
burden, and security boundary. Seams provides self-hostable threshold embedded
wallets that deploy to Cloudflare. This comparison focuses on infrastructure
ownership and operational model. Seams targets a hosted-grade wallet SDK and
user experience while keeping the wallet infrastructure self-hostable.

## Comparison

| Model | Best fit | Main tradeoff |
| --- | --- | --- |
| Hosted wallet SaaS | Teams that want provider-operated wallet infrastructure and accept provider dependency. | The wallet stack, pricing model, and roadmap stay tied to the vendor. |
| Self-hosted TEE wallet stack | Teams that can operate confidential-compute infrastructure correctly. | Security depends on enclave image, attestation, KMS, rollout, and regional availability operations. |
| Seams SDK | Teams that want self-hostable threshold embedded wallets with a low-friction Cloudflare deployment path. | Normal signing uses MPC/threshold flows, so latency is higher than single-runtime signing. |

## Hosted Wallet Clouds

Hosted wallet providers such as
[Privy](https://www.privy.io/pricing) and
[Dynamic](https://www.dynamic.xyz/pricing) are strong when a team wants the
wallet infrastructure operated by a vendor.

That is a real product advantage. It also means:

- production wallet infrastructure stays inside the provider boundary;
- pricing can become a fixed operating cost before the business is profitable;
- migration depends on the provider's export, policy, and account model;
- deep operational customization is limited by the hosted service surface.

Choose this model when vendor operation matters more than infrastructure
control.

## Self-Hosted TEE Stacks

TEE-based wallets can provide a strong server-side isolation story. The cost is
operational complexity.

Teams must manage:

- enclave images and reproducible builds;
- attestation policy;
- KMS binding;
- region placement;
- rollout and rollback procedures;
- uptime across the confidential-compute provider and every regional instance.

That can be appropriate for teams with mature infrastructure and security
operations. It is easy to underestimate the work required to keep the security
claim true after deployment.

## Seams Model

Seams uses threshold signing and hidden-share derivation. Normal signing
produces signature shares; no single runtime needs to assemble the canonical
private key.

Seams is self-hostable and serverless-friendly:

- provide hosted-grade wallet UX while retaining infrastructure control;
- deploy Router, Deriver A, Deriver B, and SigningWorker on Cloudflare Workers;
- store state in Durable Objects and role-specific storage;
- start with near-zero initial hosting cost;
- scale by sharding wallets, sessions, signing roots, and worker roles;
- preserve the same wallet architecture as deployments harden.

## Hardening Path

The default path is intentionally simple:

1. Clone the Cloudflare Worker config and GitHub Actions workflow.
2. Configure secrets and service bindings.
3. Deploy Router, Deriver A, Deriver B, and SigningWorker.

Then harden without changing the wallet architecture:

- split Deriver A and Deriver B into separate Cloudflare accounts or projects;
- use scoped deploy credentials per role;
- protect GitHub and Cloudflare admins with hardware-backed MFA;
- isolate Durable Object namespaces and role secrets;
- add approval gates and audit logging to deploy workflows;
- place sensitive roles in TEEs where required.

## Positioning

Seams starts serverless and hardens by separation. Teams can begin on
Cloudflare Workers and Durable Objects, then add stricter operational isolation
as funds, users, and policy requirements grow.

The tradeoff is straightforward: Seams spends some latency on threshold signing
to avoid a single signing runtime and to preserve deployment flexibility.

Read next:

- [Serverless Threshold Signing](/concepts/threshold-signing/serverless-threshold-signing)
- [Router A/B](/concepts/threshold-signing/router-ab)
- [Route Auth And Deployment](/concepts/advanced/route-auth-and-deployment)

---
title: Route Auth And Deployment
---

# Route Auth And Deployment

Router routes, private worker routes, wallet-session routes, and deployment
roles use separate auth boundaries.

## Public Router Boundary

Public signing routes should require Wallet Session bearer authority, strict
request-body parsing, origin policy, replay checks, quota checks, and signing
budget admission before private worker fanout.

## Private Worker Boundary

Deriver and SigningWorker private routes should be reachable only through
approved service bindings or private service auth. They should not expose public
browser CORS or parse Wallet Session credentials directly.

## Deployment Roles

Both supported Cloudflare profiles keep Router, Deriver A, Deriver B, and
SigningWorker as distinct runtime roles:

| Profile | Use | A/B transport | Security boundary |
| --- | --- | --- | --- |
| Same account | Development, staging, and latency benchmarks | Service Bindings | Separate Worker runtimes under one shared account control plane. |
| Separate accounts | Production and production-parity development | Authenticated, pinned HTTPS | Independent A and B administration, credentials, storage, logs, and deployment authority. |

The deployment profile is selected before startup. Client requests cannot
choose the topology. Same-account deployment retains isolation against a
runtime compromise confined to one Worker while the account control plane
remains honest. An account administrator can modify both roles, so the strict
production claim requires separate accounts.

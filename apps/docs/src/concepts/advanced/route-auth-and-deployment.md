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

Production Router A/B uses Router, Deriver A, Deriver B, and SigningWorker as
separate roles. Local development may bundle roles for smoke testing, but the
release security boundary is the split-role deployment.

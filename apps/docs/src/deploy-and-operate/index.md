---
title: Deploy and operate
description: Production guidance for hosting Seams wallet surfaces, protecting origins, configuring environments, observing flows, and troubleshooting.
---

# Deploy and operate

Production integration has two surfaces: the product application and the
isolated wallet runtime. Deploy each from reviewed artifacts, give each its own
origin and security policy, and keep custody-role secrets out of the browser.

Use this section to prepare a release:

1. [Host the wallet integration](/deploy-and-operate/hosted-integration).
2. Review [origin, iframe, CSP, and request-authentication
   boundaries](/deploy-and-operate/security-boundaries).
3. Assign [environment values](/deploy-and-operate/environment) to their proper
   owner.
4. Complete the [production checklist](/deploy-and-operate/production-checklist).
5. Configure [observability and audit](/deploy-and-operate/observability-and-audit).
6. Rehearse [troubleshooting](/deploy-and-operate/troubleshooting).

See [tenant-root backups](/deploy-and-operate/tenant-root-backups) for the
separate A/B recovery copies in R2, Google KMS key ownership, restore behavior,
and operating costs.

Read [recovery and portability](/deploy-and-operate/recovery-and-portability)
before choosing a backup strategy. It separates managed root recovery from
planned tenant-controlled recovery and wallet/deployment migration.

Repository operators should also follow the private deployment runbook for the
exact lane, environment, and release workflow. Public application developers do
not need custody credentials or internal service topology.

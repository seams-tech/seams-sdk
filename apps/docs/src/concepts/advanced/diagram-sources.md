---
title: Diagram Sources
---

# Diagram Sources

Architecture diagrams render in docs with Mermaid code blocks. Source copies
live under `/diagrams/` so the same diagrams can be reused in issues, plans,
and external materials.

| Diagram | Purpose |
| --- | --- |
| `/diagrams/platform-layers.mmd` | Product-layer map from proof to policy, execution, and audit. |
| `/diagrams/runtime-architecture.mmd` | Runtime component map for app origin, wallet iframe, Router, Derivers, and SigningWorker. |
| `/diagrams/router-ab-flows.mmd` | Split derivation path and normal signing path. |
| `/diagrams/custody-boundaries.mmd` | Material boundaries across client, Router, Derivers, and SigningWorker. |
| `/diagrams/delegated-lanes.mmd` | Linked-device and delegated-agent lane shape. |

SVG export is deferred until a target surface needs static images.

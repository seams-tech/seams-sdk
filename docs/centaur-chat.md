# Centaur Cloudflare Fork Chat Record

Date captured: 2026-06-27

This document captures the contents and decisions from the Centaur Cloudflare
fork discussion. Earlier parts of the thread were compacted, so older turns are
recorded as a structured transcript and decision log rather than verbatim chat
quotes.

## Starting Point

The discussion began with a review of
[paradigmxyz/centaur](https://github.com/paradigmxyz/centaur), focused on its
"multiplayer" claim and whether it can support multiple users talking to the
same agent.

Conclusion:

- Centaur's multiplayer model is Slack-thread based.
- A Slack thread maps to a durable `thread_key`, session row, execution state,
  and usually a live sandbox while the session is active.
- Multiple Slack members can participate in the same thread and thereby talk to
  the same agent session.
- Visibility follows Slack visibility. A public channel thread is effectively
  visible to channel members.
- Centaur's default blocks-mode harness appears closer to queued appended
  messages than live concurrent steering; the JSON-RPC harness has more explicit
  steering support.

## Centaur UI

Question:

- Does Centaur have its own UI, or does it plug into Slack?

Answer:

- Centaur uses Slack and API clients as chat surfaces.
- It also includes an operator/admin UI under `services/console`.
- The console is a Rails application backed by Postgres.
- The console manages credentials, principals, roles, grants, OAuth apps,
  request rules, proxies, and secret sources.
- The console is an operations dashboard, not an end-user chat UI.

Decision:

- The fork should stick to existing user interfaces where possible: Slack,
  Codex, Claude, and similar apps.
- The admin console should remain an operations surface.

## Merchant Hosting Goal

Question:

- How do we run Centaur for customers?
- Suppose there is an ecommerce platform and merchants want their own instances.

Decision:

- Build a Cloudflare-native Centaur fork.
- Avoid Kubernetes.
- Prefer a multi-tenant setup for cost efficiency.
- Keep compatibility with existing UIs.
- Preserve Centaur's core useful model: durable sessions, agent harnesses,
  credential-safe egress, typed tools, and Slack-thread collaboration.

## Cloudflare-Native Target

The proposed target stack:

| Concern | Target |
| --- | --- |
| HTTP/API ingress | Cloudflare Workers |
| Per-session coordination | Durable Objects |
| Tenant-level coordination | Durable Objects |
| Durable workflows | Cloudflare Workflows |
| Async dispatch | Queues |
| Agent execution | Cloudflare Containers / Sandbox SDK |
| Control-plane data | D1 |
| Large files and logs | R2 |
| Search/RAG | Vectorize or dedicated search layer |
| Secrets | First-party vault plus 1Password adapter |
| Egress control | Worker-side outbound handlers |
| Raw DB sessions | Local container shim plus DB Gateway Worker |

Core principle:

- Cloudflare should own the platform/runtime boundary.
- Database-level policies should be used where they materially improve data
  isolation.

## Dependency Simplification

The fork should remove or replace upstream dependencies where practical:

| Upstream dependency | Target |
| --- | --- |
| Kubernetes / Helm | Workers, Durable Objects, Containers, Queues, Workflows |
| Sandbox pods | Cloudflare Containers / Sandbox SDK |
| Postgres control plane | D1 for platform metadata |
| Rails console | TypeScript admin console on Pages/Workers |
| ActiveRecord models | D1 repositories with boundary parsers |
| iron-proxy | Worker outbound handlers and Secret Broker |
| Python service surfaces | TypeScript Workers where practical |
| 1Password-only runtime reads | Own vault primary plus 1Password adapter |

Language split:

- TypeScript for Workers, Durable Objects, Slack ingress, admin APIs, Tool
  Gateway, Secret Broker, D1 repositories, Queues, Workflows, and UI.
- Rust for DB wire shims, protocol parsers, signing/transforms, and
  performance-sensitive adapters.
- Containers only for agent harnesses and compatibility bridges.

## Secret Management

Goal:

- Support 1Password and a cheaper first-party vault.

Decision:

- Make the first-party vault the primary runtime abstraction.
- Add 1Password as an adapter or sync path.
- Agents and containers should receive placeholder values or short-lived leases,
  not raw long-lived secrets.

Secret model:

```ts
type SecretBackend =
  | { kind: "own_vault"; tenantId: TenantId; secretId: SecretId }
  | { kind: "onepassword_connect"; tenantId: TenantId; vault: OnePasswordVault; item: OnePasswordItem; field: OnePasswordField }
  | { kind: "onepassword_sync"; tenantId: TenantId; syncedSecretId: SecretId };
```

## iron-proxy On Cloudflare

Question:

- How would iron-proxy sit in front of Cloudflare Containers?

Answer:

- The better Cloudflare-native model is Worker-side outbound handling.
- Containers run without direct internet by default.
- HTTP/HTTPS egress is intercepted by trusted Worker code.
- The outbound handler resolves `container_id -> tenant/session/principal`,
  checks policy, injects credentials, and audits the request.

Temporary bridge:

- Run iron-proxy as a Cloudflare Container only as a migration bridge.
- Useful for existing `HTTPS_PROXY` clients, existing transforms, and temporary
  `pg_dsn` compatibility.
- Long-term target is Worker egress plus Secret Broker.

## Centaur Postgres TCP Proxy

Question:

- What is Centaur's Postgres TCP proxy feature?
- Why intercept specific ports?

Answer:

- Centaur/iron-control has a `pg_dsn` secret type for upstream Postgres
  credentials.
- iron-proxy can expose a Postgres listener and route sessions based on database
  name and principal grants.
- Intercepting ports matters because raw Postgres is TCP, not HTTP.
- Cloudflare container outbound handlers are strongest for HTTP/HTTPS egress.
  Raw database protocols need a different path.

## Raw DB Access On Cloudflare

Question:

- Raw DB access sounds useful. How do we do it Cloudflare-natively?

Answer:

- Run a local DB wire shim inside the container.
- The agent sees a local fake DSN such as:

```text
DATABASE_URL=postgresql://centaur:lease@127.0.0.1:15432/app
```

- The shim speaks pgwire locally and tunnels bytes over HTTPS/WebSocket to a DB
  Gateway Worker.
- The DB Gateway validates tenant, session, principal, database alias, lease,
  expiry, mode, protocol, schema scope, approval state, and budget.
- The gateway opens outbound TCP to the merchant database using Workers TCP
  sockets where appropriate.
- Hyperdrive is useful for Worker-executed SQL paths and pooled known
  Postgres/MySQL connections.
- The raw byte-forwarded session path is a separate gateway mode.

Recommended database modes:

| Mode | Audience | Implementation |
| --- | --- | --- |
| Typed tools | Merchant operations | Tool Gateway |
| SQL tool | Controlled ad hoc SQL | Worker DB client / Hyperdrive / TCP |
| Raw DB session | Developer agents and privileged ops | Local shim to DB Gateway |

## Typed Tools Versus Raw DB Access

Question:

- Can typed tools replicate raw DB access from the container well enough?

Conclusion:

- Typed tools should cover normal merchant workflows.
- Raw DB remains useful for developer agents, migrations, ORM CLIs, schema
  inspection, data repair, debugging, and tests that expect `DATABASE_URL`.
- Support both, with raw DB gated as an explicit privileged capability.

## Durable Workflows

Question:

- What does Centaur use Postgres for?
- Does it use Postgres for durable workflows?
- What is a durable workflow?

Centaur Postgres usage:

- Durable agent sessions: `sessions`, `session_messages`,
  `session_executions`, `session_events`.
- Workflow runtime state through Absurd: tasks, run attempts, checkpoints,
  emitted events, waits, idempotency keys, leases.
- Synced context data: Slack, Google Drive, Calendar, Linear, company context
  documents, search indexes.
- Console/secret management state in the Rails console.
- Read-only views and RLS policies for context access and operator access.

Definition:

- A durable workflow is a long-running orchestration whose progress is saved at
  meaningful steps.
- If a worker restarts, the handler can run again and reuse completed step
  results.
- It can sleep, retry, wait for external events, call tools, call agents, and
  start child workflows.

Example:

```text
convert_pdf_to_docx workflow
  -> store PDF in R2
  -> run converter in a container
  -> validate output
  -> optionally ask agent to inspect or fix formatting
  -> deliver DOCX to Slack or app UI
```

Conclusion:

- For deterministic conversion, use a tool or container job.
- Use the agent for judgment-heavy steps such as inspection, extraction,
  summarization, or repair.

## Absurd Versus Cloudflare Workflows

Question:

- Is durable workflow better on Absurd or Cloudflare-native?

Conclusion:

- For upstream Centaur, Absurd fits because the system already depends on
  Postgres.
- For the Cloudflare-native fork, Cloudflare Workflows should be the default.
- Keeping Absurd keeps Postgres as a core runtime dependency.
- Cloudflare Workflows covers durable steps, retries, sleeps, wait-for-event,
  and long-running orchestration.
- Use D1 for workflow indexes and metadata, R2 for large payloads, Queues for
  fanout, and Durable Objects for per-session or per-tenant coordination.

Cloudflare mapping:

| Absurd/Centaur concept | Cloudflare-native concept |
| --- | --- |
| `ctx.step` | Workflow step |
| `ctx.sleep` / `ctx.sleep_until` | Workflow sleep |
| `await_event` | Workflow wait for event |
| `emit_event` | Send event to workflow instance |
| Task/checkpoint tables | Workflow state plus D1/R2 indexes |
| Worker leases | Managed Workflow execution |
| Python workflow host | TypeScript Workflow or temporary container bridge |
| Agent turn | Session Durable Object / Agent Runner call |

## Slack Commerce UI

Question:

- Does Slack offer widgets that make it easy to replicate Shopify functionality:
  product upload, inventory, orders, and similar workflows?

Answer:

- Slack can support many lightweight commerce operations through Block Kit,
  modals, file inputs, App Home, data tables, Work Objects, and flexpane.
- It should handle high-frequency actions, approvals, exception queues, imports,
  and short forms.
- Dense catalog browsing, complex variant editing, advanced analytics, and long
  setup flows can live in a small web console or an external system.

Later clarification:

- A full Shopify Admin clone is likely unnecessary for an ecommerce AI agent.
- The agent can use direct APIs to update listings.
- Slack can be the approval and exception surface.
- Spreadsheets and Airtable-like systems may be easier for merchant-facing
  listing maintenance, although that idea was kept out of the plan until an
  explicit decision is made.

## Shopify Backend Clone Discussion

Question:

- If we created our own Shopify backend clone on Cloudflare, would it have a
  structural cost advantage over Shopify plans?

Discussion:

- Potential cost advantage exists if the platform avoids Shopify app fees,
  checkout fees, and plan costs.
- The difficult work shifts into payments, tax, shipping, disputes,
  reconciliation, compliance, refunds, fraud, product modeling, order state, and
  integrations.
- Stripe, Airwallex, and similar providers can handle checkout/payments.
- Shipping can use direct courier APIs or aggregators.
- Tax is more complex than basic math; VAT, nexus, exemptions, product tax
  categories, jurisdictions, evidence, and filing rules matter.

Recommendation:

- Use Stripe Tax, TaxJar, Avalara, or similar first.
- Avoid owning the full tax engine early.

## Tenant Isolation

Goal:

- Host Centaur for multiple merchants and give each merchant meaningful
  isolation.

Default recommendation:

- Use pooled multi-tenancy by default.
- Add dedicated data resources for larger merchants.
- Add dedicated deployments for enterprise or regulated merchants.

Isolation tiers:

| Tier | Shape | Use case |
| --- | --- | --- |
| Pooled tenant | Shared Workers, D1, R2, Workflows, Queues, and search with strict tenant keys | Default merchant tier |
| Dedicated data | Shared code with dedicated R2 bucket, search index, vault namespace, or D1 database | Larger merchants |
| Dedicated deployment | Separate Cloudflare account, Workers, bindings, storage, vault, and Slack app | Enterprise merchants |

Tenant boundaries:

- Slack `team_id` maps to a tenant install.
- Tenant Durable Object owns status, quotas, locks, plan state, and high-level
  config.
- Session Durable Object IDs include tenant and session identity.
- Workflow instance IDs include tenant identity.
- Containers are per agent run or warm session.
- Secret Broker resolves only tenant-granted `SecretRef` values.
- Egress handlers check `container_id -> tenant/session/principal`.
- DB Gateway validates tenant, principal, alias, lease, mode, and budget.
- D1 tables include `tenant_id`.
- R2 objects live under `tenants/{tenant_id}/...`.
- Search queries require tenant metadata filters.
- Audit records include tenant, principal, action, resource, and decision.

## Cloudflare Versus Postgres Tenant Isolation

Question:

- Is tenant isolation better on Cloudflare or Postgres?

Conclusion:

- Postgres is better for shared-table data isolation because row-level security
  is enforced in the database engine.
- Cloudflare is better for platform/runtime isolation: containers, Workers,
  Durable Objects, egress, secrets, quotas, and merchant-owned code.
- D1 has SQLite semantics and no Postgres-style RLS, so shared D1 isolation is
  enforced in the app/repository layer.
- Stronger Cloudflare-native data isolation can use per-tenant D1, R2, DO
  storage, and search resources.

Recommendation:

- Keep the platform Cloudflare-native.
- Use Postgres RLS only where database-enforced shared relational isolation is
  worth the dependency.

## Multiple D1 Databases

Question:

- Can we provision multiple D1 databases for tenant isolation?

Answer:

- Yes.
- D1 supports many databases and is priced by queries and storage rather than a
  per-database flat charge.
- Per-tenant D1 improves blast-radius isolation, export/delete workflows, and
  dedicated data tier boundaries.
- The tradeoff is migration fanout, runtime routing, and cross-tenant analytics.

Suggested model:

```text
shared control-plane D1
  tenants
  tenant_resource_bindings
  slack_installs
  plans
  routing metadata

per-tenant D1
  merchant catalog/cache
  tenant context metadata
  workflow business state
  integration state
```

Provisioning flow:

```text
admin/API onboarding
  -> create tenant row in shared D1
  -> call Cloudflare API to create D1 database
  -> apply schema migrations
  -> store database_id in tenant_resource_bindings
  -> mark tenant ready
```

Recommendation:

- Use shared D1 for pooled control-plane metadata.
- Add per-tenant D1 for dedicated data tiers.
- Avoid hot-path dependence on D1 REST API queries for high-volume tenant data.
  Prefer bound resources or tenant-bound service/dispatch paths.

## Local Development

Question:

- How do we develop `centaur-cloudflare` locally?
- Can we have a local D1/SQLite instance?

Answer:

- Yes. D1 local development is first-class through Wrangler and Miniflare.
- `wrangler dev` creates local versions of bound resources.
- Local D1 data is separate from remote data.
- Local state can live under `.wrangler/state` or a project-specific path such
  as `.wrangler/local-state`.

Recommended local stack:

```text
wrangler dev
  -> local Workers runtime
  -> local D1 bindings
  -> local Durable Objects
  -> local R2 buckets
  -> local Queues
  -> local/emulated Workflows
  -> local Cloudflare Containers or Docker fallback
```

Recommended commands:

```bash
pnpm wrangler d1 create centaur-control-dev
pnpm wrangler d1 migrations create centaur-control-dev init
pnpm wrangler d1 migrations apply centaur-control-dev --local
pnpm wrangler d1 execute centaur-control-dev --local --file ./seeds/dev.sql
pnpm wrangler dev --persist-to .wrangler/local-state
```

Tenant fixture modes:

| Mode | Local approach |
| --- | --- |
| Pooled default | One `CONTROL_DB`, seeded with multiple tenants |
| Dedicated tenant simulation | Fixed local bindings such as `TENANT_DB_ALPHA` and `TENANT_DB_BRAVO` |
| Unit tests | Thin repository tests may use plain SQLite fixtures |
| Integration tests | Miniflare or `wrangler dev` should exercise real D1 bindings |

Boundary type:

```ts
type TenantDatabaseRef =
  | { kind: "pooled"; tenantId: TenantId; binding: "CONTROL_DB" }
  | { kind: "dedicated"; tenantId: TenantId; binding: TenantD1Binding };
```

Local test requirements:

- Seed at least two tenants.
- Seed Slack installs, principals, roles, grants, secret refs, quotas, resource
  bindings, sessions, and DB aliases.
- Add cross-tenant denial tests for D1, R2, search, egress, and DB leases.
- Run raw DB gateway integration tests against a Docker Postgres instance.

## Plan Document Updates

The main plan lives at:

- [docs/centaur-cloud-fork.md](centaur-cloud-fork.md)

Major updates made during the discussion:

- Reorganized and slimmed duplicate sections.
- Emphasized Cloudflare-native migration as the main goal.
- Added dependency simplification from Kubernetes/Rails/Postgres/Python toward
  TypeScript/Rust plus Cloudflare primitives.
- Compared D1 and Postgres.
- Documented Centaur's Postgres usage.
- Replaced Absurd as the target durable workflow runtime with Cloudflare
  Workflows.
- Added Slack commerce operations.
- Added raw DB access and DB Gateway design.
- Added pooled multi-tenant isolation model.
- Added per-tenant D1 strategy.
- Added local development model with local D1 and Miniflare.

## External References Discussed

Cloudflare:

- https://developers.cloudflare.com/containers/
- https://developers.cloudflare.com/containers/platform-details/outbound-traffic/
- https://developers.cloudflare.com/durable-objects/
- https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- https://developers.cloudflare.com/d1/
- https://developers.cloudflare.com/d1/best-practices/local-development/
- https://developers.cloudflare.com/d1/platform/limits/
- https://developers.cloudflare.com/workers/local-development/local-data/
- https://developers.cloudflare.com/queues/
- https://developers.cloudflare.com/queues/configuration/local-development/
- https://developers.cloudflare.com/workflows/
- https://developers.cloudflare.com/workflows/build/local-development/
- https://developers.cloudflare.com/workflows/reference/limits/
- https://developers.cloudflare.com/r2/
- https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- https://developers.cloudflare.com/hyperdrive/
- https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/
- https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/bindings/
- https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/outbound-workers/
- https://developers.cloudflare.com/secrets-store/

Postgres:

- https://www.postgresql.org/docs/current/ddl-rowsecurity.html

Slack:

- https://docs.slack.dev/block-kit/
- https://docs.slack.dev/reference/block-kit/block-elements/file-input-element
- https://docs.slack.dev/reference/block-kit/blocks/data-table-block/
- https://docs.slack.dev/messaging/work-objects-overview/
- https://docs.slack.dev/surfaces/app-home

Upstream:

- https://github.com/paradigmxyz/centaur

# Cloudflare-Native Centaur Fork Plan

Last reviewed: 2026-06-26

## Executive Summary

This plan describes a Cloudflare-native fork of
[paradigmxyz/centaur](https://github.com/paradigmxyz/centaur) for a
multi-tenant merchant platform. The main goal is migration to a Cloudflare-native
architecture with a smaller dependency surface. The fork preserves Centaur's
useful interaction model: Slack/API ingress, durable sessions, shared
Slack-thread collaboration, agent harnesses, credential boundaries, and
operator-managed grants. It replaces the Kubernetes production substrate with
Cloudflare Workers, Durable Objects, Containers, D1, R2, Queues, Workflows,
Hyperdrive, and Worker-side secret brokerage.

The product should use existing user interfaces wherever possible. Slack is the
primary multiplayer surface. Codex, Claude, and similar apps are harnesses or
developer/operator surfaces. The admin console remains an operations surface for
tenants, installs, grants, secrets, audit, and raw database access controls.

Centaur's upstream production model uses Postgres, Kubernetes sandbox pods, and
iron-proxy. The Cloudflare fork should keep the security contract while changing
the implementation: agent containers do not receive merchant credentials; typed
tools, egress handlers, and database gateways perform privileged work in trusted
Worker code.

Related architecture plans:

- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)

## Key Decisions

1. Make the fork Cloudflare-native rather than a Kubernetes deployment.
2. Run one pooled multi-tenant platform for many merchants by default.
3. Offer dedicated data and dedicated deployment tiers for larger merchants.
4. Use Slack as the primary collaborative UI.
5. Use Cloudflare-native Workers, Durable Objects, and Containers instead of
   Kubernetes.
6. Replace iron-proxy with a Worker-side credential and egress boundary.
7. Keep an iron-proxy container bridge only as a temporary compatibility path.
8. Prefer a TypeScript/Rust stack over Rails and Python service dependencies.
9. Use typed tools for merchant operations by default.
10. Add raw database sessions as an explicit privileged capability.
11. Store merchant credentials in a first-party vault, with 1Password as an
   adapter.
12. Require tenant identity in every core domain object and persistence access
   path.
13. Use Workers for Platforms only when merchants can upload custom code.
14. Keep shared Cloudflare Workflows in the platform account, keyed by
    `tenant_id`.
15. Keep Slack chat, commerce actions, raw DB access, and admin operations as
    separate capability surfaces.
16. Model humans, agents, and services as first-class principals that can share
    the same team, role, grant, and audit schema.
17. Use member access modes to distinguish direct access from proxy-only
    delegated credential use.

## Dependency Simplification

The fork should treat Cloudflare-native migration and dependency reduction as
one project. Upstream Centaur's production shape includes Kubernetes, Postgres,
Rails console services, Python/FastAPI-era service surfaces, sandbox pods, and
iron-proxy. The target stack should be mostly TypeScript Workers plus Rust for
protocol-heavy or performance-sensitive components.

| Upstream dependency | Keep, remove, or replace | Target |
| --- | --- | --- |
| Kubernetes / Helm | Replace | Cloudflare Workers, Durable Objects, Containers, Queues, Workflows |
| Sandbox pods | Replace | Cloudflare Containers / Sandbox SDK |
| Postgres as control-plane DB | Replace for platform metadata | D1 for tenants, sessions, grants, audit indexes |
| Postgres for raw merchant DB access | Keep as external customer capability | DB Gateway, Hyperdrive, Workers TCP sockets |
| Rails console / iron-control-style UI | Replace | TypeScript admin console on Pages/Workers |
| Rails ActiveRecord models | Replace | D1 repositories with strict boundary parsers |
| iron-proxy | Replace | Worker outbound handlers and Secret Broker |
| iron-proxy bridge | Temporary only | Cloudflare Container compatibility bridge |
| Python service surfaces | Replace where practical | TypeScript Workers; Rust only where it earns its cost |
| 1Password-only runtime secret reads | Generalize | Own vault primary, 1Password adapter/sync path |

Recommended language split:

- **TypeScript** for Workers, Durable Objects, Slack ingress, admin console APIs,
  Tool Gateway, Secret Broker orchestration, D1 repositories, Queues, Workflows,
  and UI.
- **Rust** for database wire shims, protocol parsers, signing/transforms that
  need stronger correctness guarantees, and optional high-throughput adapters.
- **Container images** only for agent harnesses and compatibility bridges.

Postgres should be removed from the platform control plane first. D1 is a better
fit for Cloudflare-hosted tenant metadata, grants, sessions, execution state,
and audit indexes. Postgres remains relevant as a merchant resource that agents
may access through the DB Gateway.

Rails should be replaced rather than ported. The console's job is narrow:
tenants, Slack installs, principals, roles, grants, secrets, DB aliases, audit,
and usage. That maps cleanly to a TypeScript admin API and a small Pages UI.

## Target Architecture

```text
Slack / Codex / Claude / API clients
   |
Ingress Worker
   |
Tenant Resolver + Auth
   |----------------------|
   |                      |
D1 control plane      Tenant Durable Object
                          |
Session Durable Object
   |
Queues / Workflows
   |
Agent Container Durable Object
   |
Per-session Cloudflare Container / Sandbox SDK
   |
HTTP(S) egress handler       local DB shim
   |                         |
Egress Gateway               WebSocket over HTTPS
   |                         |
Secret Broker                DB Gateway Worker
   |                         |
Own Vault / 1Password        Workers TCP sockets / SQL gateway
   |                         |
Merchant APIs / LLMs         Merchant databases
```

| Component | Cloudflare service | Main implementation | Responsibility |
| --- | --- | --- | --- |
| Ingress Worker | Workers | TypeScript | Slack/API webhooks, signing checks, tenant resolution |
| Session Coordinator | Durable Objects | TypeScript | Per-thread state, active-run lock, stream fanout, cancellation |
| Runner | Containers / Sandbox SDK | Container image + TypeScript owner | Codex, Claude Code, and other agent harnesses |
| Async Work | Queues / Workflows | TypeScript | Run dispatch, retries, approvals, scheduled jobs |
| State | D1 | TypeScript repositories | Tenants, installs, principals, grants, sessions, executions, audit indexes |
| Artifacts | R2 | TypeScript | Transcripts, files, previews, large logs, encrypted blobs |
| Egress | Workers + container outbound handlers | TypeScript, Rust where useful | HTTP/HTTPS policy, credential injection, audit |
| Secrets | Secret Broker + vault | TypeScript | Own vault, 1Password adapter, wrapping keys |
| Databases | Workers TCP sockets / Hyperdrive | Rust shim + TypeScript gateway | Raw DB sessions, SQL tools, pooled database paths |

## Multi-Tenant Isolation Strategy

The default product should be a pooled platform deployment. Shared Workers,
Workflow classes, D1 databases, R2 buckets, Vectorize indexes, and Queues keep
costs low while tenant-aware domain types, repositories, Durable Objects,
egress policies, and audit records enforce isolation.

Default pooled shape:

- One shared platform Worker/API.
- One shared D1 control-plane database.
- One shared set of Workflow classes.
- One shared R2 bucket with tenant-prefixed object keys.
- One shared search layer with required tenant filters.
- One Tenant Durable Object per merchant.
- One Session Durable Object per Slack thread or API session.
- One container per live agent task or warm agent session.
- Tenant-scoped secrets, grants, quotas, audit logs, tool permissions, Slack
  installs, DB aliases, and DB leases.

Isolation tiers:

| Tier | Shape | Use case |
| --- | --- | --- |
| Pooled tenant | Shared code, D1, R2, Workflows, Queues, and search with strict tenant keys | Default merchant tier |
| Dedicated data | Shared code with dedicated R2 bucket, search index, vault namespace, or D1 database | Larger merchants with stronger data boundaries |
| Dedicated deployment | Separate Cloudflare account, Workers, bindings, storage, vault, and Slack app | Enterprise or regulated merchants |

Isolation boundaries:

| Layer | Isolation model |
| --- | --- |
| Slack install | Slack `team_id` or enterprise ID maps to a tenant install record |
| Tenant coordination | `TenantDO` owns plan status, quotas, tenant locks, and high-level config |
| Session coordination | `SessionDO` ID includes tenant and thread/session identity |
| Workflows | Shared Workflow class; instance IDs and persisted metadata include tenant identity |
| Containers | One workspace per agent run or warm session; no shared filesystem across tenants |
| Secrets | Secret Broker resolves only tenant-granted `VaultFieldRef` values |
| HTTP/HTTPS egress | Container outbound handler checks `container_id -> tenant/session/principal` |
| Raw DB access | DB Gateway validates tenant, principal, alias, lease, mode, and budget |
| D1 | Every table uses `tenant_id`; repository inputs require parsed tenant context |
| R2 | Object keys live under `tenants/{tenant_id}/...` |
| Search | Every query includes tenant metadata filters; dedicated indexes are available by tier |
| Audit | Every decision records tenant, principal, resource, action, and outcome |
| Quotas | Tenant DO enforces concurrency, spend, workflow, storage, tool, and DB limits |

Workers for Platforms is a later extension for merchant-owned code or generated
code. The core Centaur fork can run as a multi-tenant platform without it. If
merchant code becomes a product feature, route requests through a dynamic
dispatch Worker, put merchant Workers in a dispatch namespace, attach only the
bindings that merchant should receive, and route outbound fetches through an
outbound Worker. Cloudflare Workflows should remain platform-owned because
Workflows currently cannot be deployed into Workers for Platforms namespaces.

The design should preserve an upgrade path between tiers. Tenant IDs, storage
keys, Workflow instance IDs, queue payloads, and secret references should be
portable so a merchant can move from pooled storage to dedicated resources
without changing Slack behavior or agent-visible capabilities.

## Tenant, Principal, And Session Model

Every internal request must carry a parsed `TenantContext`. The ingress boundary
validates raw external identifiers once, then core logic operates on precise
internal types.

Thread keys should include tenant identity:

```text
tenant:{tenant_id}:slack:{team_id}:{channel_id}:{thread_ts}
tenant:{tenant_id}:api:{client_id}:{session_id}
tenant:{tenant_id}:codex:{workspace_id}:{session_id}
```

Boundary inputs:

| Source | Raw identifiers normalized at ingress |
| --- | --- |
| Slack | `team_id`, `channel_id`, `thread_ts`, `user_id`, install ID |
| API | API key, OAuth subject, client ID, session ID |
| Agent app | Workspace/project ID, session ID |
| Persistence | D1 rows, Queue messages, stored session state |

Core invariants:

- Tenant ID is required on every principal, session, grant, secret, execution,
  DB lease, and audit event.
- Tenant context is resolved once at ingress and passed as a required internal
  type.
- Tenant Durable Object identity is derived from `tenant:{tenant_id}`.
- Session Durable Object identity is derived from
  `tenant:{tenant_id}:session:{session_id}`.
- Workflow instance IDs include tenant and business identity where idempotency
  matters.
- Container IDs include tenant, session, execution, and runner identity.
- Core functions accept precise domain types, not raw Slack payloads, raw DB
  rows, partial objects, or optional identity fields.
- D1 has no row-level security. Tenant isolation is enforced by typed
  repositories, required tenant IDs, and targeted cross-tenant denial tests.
- Compatibility parsing belongs at request and persistence boundaries.

Suggested principal and membership shape:

```ts
type Principal =
  | { kind: "human"; tenantId: TenantId; principalId: PrincipalId }
  | { kind: "agent"; tenantId: TenantId; principalId: PrincipalId; agentId: AgentId }
  | { kind: "service"; tenantId: TenantId; principalId: PrincipalId; serviceId: ServiceId }
  | { kind: "system"; tenantId: TenantId; actor: SystemActor };

type PrincipalExternalIdentity =
  | { kind: "slack_user"; tenantId: TenantId; principalId: PrincipalId; teamId: SlackTeamId; userId: SlackUserId }
  | { kind: "api_client"; tenantId: TenantId; principalId: PrincipalId; clientId: ApiClientId };

type MemberAccessMode =
  | { kind: "direct_member"; canRevealSecrets: boolean; canManageGrants: boolean; canDelegateAccess: boolean }
  | { kind: "delegate_member"; proxyOnly: true }
  | { kind: "metadata_only" }
  | { kind: "approval_only" };

type TeamMembership = {
  tenantId: TenantId;
  teamId: TeamId;
  principalId: PrincipalId;
  roleId: RoleId;
  accessMode: MemberAccessMode;
};
```

Agents default to `delegate_member`, which permits credential use only through
trusted proxy boundaries such as Egress Gateway, DB Gateway, or Model Gateway.
Teams can explicitly promote an agent to `direct_member`; that should be visible
in admin UI and audit.

Slack install model:

- Use one platform Slack app installed into each merchant workspace.
- Verify events with the platform signing secret.
- Store each workspace bot token as an encrypted secret reference.
- Resolve Slack `team_id` to tenant install records.
- Use channel-level or App Home configuration when one Slack workspace maps to
  multiple tenants.
- Add per-merchant Slack apps later for enterprise isolation if needed.

Session model:

- One Session Durable Object owns each Slack thread or API session.
- The Session Durable Object serializes messages, tracks lifecycle, fans out
  streamed events, persists durable state, and starts runner work through
  Queues.
- Slack-thread "multiplayer" comes from shared thread visibility. Multiple
  Slack members can write into the same durable session.

Minimal lifecycle shape:

```ts
type SessionLifecycle =
  | { kind: "idle"; tenantId: TenantId; sessionId: SessionId }
  | { kind: "queued"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId }
  | { kind: "running"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId; runnerId: RunnerId }
  | { kind: "cancelling"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId; requestedBy: Principal }
  | { kind: "terminal"; tenantId: TenantId; sessionId: SessionId; terminal: TerminalState };
```

## Runtime Model

### Ingress Worker

The Ingress Worker handles Slack events, API requests, and app callbacks:

- Verify Slack signatures and API auth.
- Resolve tenant and principal.
- Normalize request payloads into domain commands.
- Write events to the Session Durable Object.
- Enqueue work for async processing.
- Reject unknown tenants, revoked installs, disabled tenants, and malformed
  thread keys at the boundary.

### Tenant Durable Object

The Tenant Durable Object is the coordination point for one merchant:

- Owns tenant status, plan limits, and temporary suspension state.
- Enforces active session, active container, raw DB, workflow, and spend quotas.
- Serializes tenant-wide operations such as Slack reinstall, vault rotation,
  dedicated resource migration, and emergency disable.
- Stores small hot config needed for fast request decisions.
- Emits audit events for quota denials and administrative state changes.

### Session Durable Object

The Session Durable Object is the coordination point for one agent session:

- Owns active-run locking.
- Stores compact mutable session state.
- Persists durable messages and execution state to D1/R2.
- Streams output to Slack delivery and optional web clients.
- Handles cancellation and final delivery retries.
- Starts agent runs through Queues.

### Container Runner

The container runner executes Codex, Claude Code, or other harnesses inside a
Cloudflare Container:

```text
container_id = tenant:{tenant_id}:session:{session_id}:runner:{runner_id}
```

Runner behavior:

- Start one container per active run or explicitly warm session.
- Mount no merchant credentials.
- Provide prompts, transcript files, workspace state, and tool catalog config.
- Provide placeholder environment variables for clients that require API-key
  shaped values.
- Route HTTP/HTTPS egress through outbound handlers.
- Route raw DB access through the local DB shim and DB Gateway.
- Persist outputs and artifacts to R2.
- Destroy idle temporary sandboxes aggressively.

Where a harness supports a custom model base URL, route model calls through a
Model Gateway. Harnesses that call vendors directly should use placeholder
credentials and egress transforms.

## Credential And Egress Boundary

This section replaces the separate iron-proxy and Secret Broker concepts with a
single boundary: trusted Worker code owns credentials, policy checks, request
rewrites, database leases, and audit records.

### Secret Broker

Make the first-party vault the primary runtime abstraction. Add 1Password as an
adapter. The detailed vault object model lives in
[Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md).

```ts
type VaultFieldRef = {
  kind: "vault_field_ref";
  tenantId: TenantId;
  itemId: VaultItemId;
  fieldId: VaultFieldId;
};
```

Own vault:

- D1 stores secret metadata, labels, grants, status, and rotation state.
- R2 or D1 stores encrypted payload blobs.
- Cloudflare Secrets Store or Worker secrets hold platform bootstrap material.
- Secret Broker decrypts only inside trusted Worker code.
- Per-tenant data keys limit blast radius.
- Admin callers can write or rotate secret values, while readback returns only
  metadata.

1Password modes:

- `onepassword_connect` resolves live through a customer or platform Connect
  service.
- `onepassword_sync` imports selected items into the first-party vault for
  cheaper runtime reads.
- Service-account automation can seed or rotate values.

### HTTP And HTTPS Egress

Cloudflare-native egress is the target replacement for iron-proxy's core
credential substitution behavior.

Container settings:

```text
enableInternet = false
interceptHttps = true
allowedHosts = policy-derived allowlist
```

The outbound handler:

- Resolves container ID to tenant, session, execution, and principal.
- Loads the effective egress policy.
- Denies unknown hosts.
- Matches host, method, path, headers, and query params.
- Resolves secrets from Secret Broker.
- Injects headers, query params, bearer tokens, OAuth tokens, GCP tokens, and
  AWS SigV4 signatures.
- Replaces placeholder values in approved request locations.
- Emits an audit event before forwarding.

Centaur mapping:

| Centaur concept | Cloudflare-native concept |
| --- | --- |
| iron-control principal | Tenant principal and grants |
| proxy ID | Container/session ID |
| proxy sync | Egress policy revision |
| secret source | `VaultFieldRef` |
| `replace.proxy_value` | Placeholder replacement rule |
| `inject.header/query` | Request rewrite rule |
| `rules.host` | Host allowlist rule |
| proxy audit | Audit event plus R2 payload |

### Iron-Proxy Bridge

Use an iron-proxy container bridge only for migration compatibility:

- Prove upstream Centaur tool compatibility.
- Keep `HTTPS_PROXY`-dependent clients working during the port.
- Test existing transform fragments before translating them.
- Support `pg_dsn` temporarily while the DB Gateway is implemented.

The bridge should be time-boxed. The target path is Worker-side egress and
Secret Broker logic.

## Capability Surfaces

| Surface | Primary user | Interface | Backend |
| --- | --- | --- | --- |
| Slack commerce operations | Merchant operators | Threads, modals, App Home, data tables | Typed tools |
| Typed tool gateway | Agent harnesses | HTTPS/internal service calls | Worker Tool Gateway |
| SQL tool | Operators and agents | Tool call | Worker DB client, Hyperdrive, or TCP |
| Raw DB session | Developer agents and privileged ops | Local DSN in container | DB Gateway |
| Admin console | Operators and merchant admins | Pages/Workers app | D1/R2/Secret Broker |

### Slack Commerce Operations

Slack should cover high-frequency operations, approvals, exception handling,
lightweight edits, and bulk import review. Dense catalog browsing, complex
variant editing, deep analytics, and long-running setup can live in the web
console or an external merchant system.

| Workflow | Slack primitive | Backend tool | Approval |
| --- | --- | --- | --- |
| Product CSV upload | File input, preview table | `products.import_preview`, `products.import_apply` | Required before apply |
| Inventory exception | App Home queue, data table, modal | `inventory.search`, `inventory.adjust` | Required for high-risk adjustments |
| Order triage | Order card, buttons, modal | `orders.get`, `orders.fulfill`, `orders.refund`, `orders.cancel` | Required for money/customer-visible mutations |
| Bulk import result | Thread summary, artifact link | Import Worker, R2 report | Result-only |
| Entity detail | Work Object, flexpane | `products.get`, `orders.get`, `customers.get` | Role-gated rendering |

Product import flow:

```text
merchant uploads CSV in Slack
  -> Tool Gateway downloads file with Slack bot token
  -> Import Worker stores raw file in R2
  -> parser validates rows and normalizes product drafts
  -> agent posts preview table and error summary
  -> merchant confirms import
  -> Tool Gateway writes products through commerce adapter
  -> final Slack report links to import artifact and changed products
```

Slack App Home should show per-user operational queues: connection status,
pending approvals, failed automations, low-stock items, order exceptions, bulk
imports, saved searches, and common actions.

### Typed Tool Gateway

Typed tools are the default merchant capability surface:

```text
shopify.orders.search
shopify.orders.refund
shopify.inventory.adjust
stripe.refunds.create
merchant.customers.lookup
merchant.reports.run_sql_readonly
```

The Tool Gateway enforces tenant, principal, channel, role, tool allowlist,
secret grant, approval, spend, rate, budget, and idempotency policy. Merchant
credentials flow only into Tool Gateway calls.

### Raw Database Access

Typed tools cover common merchant operations. Raw DB access remains useful for
developer-style agents: schema inspection, migrations, `psql`, ORM CLIs,
application debugging, data repair, and tests that expect a normal
`DATABASE_URL`.

Support three database modes:

| Mode | Default audience | Implementation |
| --- | --- | --- |
| Typed tools | Merchant operations | Tool Gateway over HTTPS |
| SQL tool | Controlled ad hoc SQL | Worker executes SQL through a driver, Hyperdrive, or TCP |
| Raw DB session | Developer agents and privileged ops | Local container shim to DB Gateway |

Raw session path:

```text
agent / psql / ORM
  -> localhost:15432 inside container
  -> pgwire shim
  -> WebSocket over HTTPS to db.internal
  -> DB Gateway Worker
  -> Workers TCP socket
  -> merchant Postgres
```

The container receives a fake local DSN:

```text
DATABASE_URL=postgresql://centaur:lease@127.0.0.1:15432/app
```

The DB Gateway validates tenant, session, principal, database alias, lease,
expiry, protocol, mode, schema scope, connection limits, budget, and approval
state. Enforcement should rely on database roles and gateway limits: readonly by
default, schema-specific grants, statement timeouts, idle transaction timeouts,
connection limits, no superuser, short leases, and explicit migration grants.

Use Hyperdrive for Worker-executed SQL paths against known Postgres/MySQL
databases where pooling matters. Use direct Worker TCP sockets for raw
byte-forwarded database sessions. Verify private database connectivity before
making customer commitments.

### Admin Console

The admin console should remain focused:

- Tenant creation and status.
- Slack install and reinstall flow.
- Principal discovery and role assignment.
- Tool grants.
- Secret references and vault sync.
- DB aliases, DB leases, and raw DB access approvals.
- Audit search.
- Usage and cost reporting.

## Persistence Model

Core D1 tables:

```text
tenants(id, slug, plan, status, created_at)
tenant_resource_bindings(tenant_id, tier, resource_kind, binding_name, external_id, status)
tenant_quotas(tenant_id, quota_kind, limit_value, window_seconds, status)
tenant_usage_windows(tenant_id, quota_kind, window_start, used_value)
slack_installs(tenant_id, team_id, bot_token_secret_ref, scopes, installed_by)
principals(tenant_id, principal_id, kind, foreign_id, display_name)
roles(tenant_id, role_id, name)
principal_roles(tenant_id, principal_id, role_id)
teams(tenant_id, team_id, name, status, created_by)
team_memberships(tenant_id, team_id, principal_id, role_id, access_mode_kind, access_mode_json, status)
secrets(tenant_id, secret_id, backend_kind, ref, encrypted_blob_ref, labels, status)
grants(tenant_id, grant_id, grantee_kind, grantee_id, resource_kind, resource_id, policy_json)
sessions(tenant_id, session_id, thread_key, source, lifecycle, active_execution_id, created_at)
messages(tenant_id, session_id, message_id, role, author_principal_id, parts_ref, created_at)
executions(tenant_id, execution_id, session_id, status, runner_id, started_at, completed_at)
events(tenant_id, session_id, event_id, execution_id, type, payload_ref, created_at)
db_leases(tenant_id, lease_id, principal_id, db_alias, mode, expires_at, policy_json)
audit_events(tenant_id, audit_id, actor_principal_id, action, resource, decision, metadata_ref, created_at)
```

R2 key shape:

```text
tenants/{tenant_id}/sessions/{session_id}/...
tenants/{tenant_id}/executions/{execution_id}/...
tenants/{tenant_id}/audit/{date}/{audit_id}.json
tenants/{tenant_id}/imports/{import_id}/...
```

Audit events should cover:

- Slack ingress.
- Session lifecycle transitions.
- Agent execution start, finish, and cancel.
- Tool calls and policy decisions.
- Secret access decisions.
- HTTP egress decisions and transforms.
- DB lease creation.
- DB connection open and close.
- Raw DB session byte counts and duration.
- Admin console changes.

Avoid logging secret values, raw authorization headers, full OAuth tokens, raw
database passwords, and customer PII unless the event type explicitly requires
it.

## Local Development Model

Local development should use Wrangler and Miniflare as the default runtime.
Cloudflare D1 supports local development through Wrangler, with local data
separate from production data. Miniflare creates local versions of bound
resources such as D1, R2, KV, Queues, and Durable Objects when the dev session
starts.

Local stack:

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

Suggested repo layout:

```text
apps/platform-worker/
  src/
  migrations/
  seeds/
  wrangler.jsonc

packages/domain/
packages/d1-repositories/
packages/tool-gateway/
packages/secret-broker/
packages/db-gateway/
```

Suggested local `wrangler.jsonc` bindings:

```jsonc
{
  "name": "centaur-cloudflare",
  "main": "src/worker.ts",
  "compatibility_date": "2026-06-27",
  "d1_databases": [
    {
      "binding": "CONTROL_DB",
      "database_name": "centaur-control-dev",
      "database_id": "replace-with-dev-d1-id",
      "preview_database_id": "centaur-control-local"
    },
    {
      "binding": "TENANT_DB_ALPHA",
      "database_name": "centaur-tenant-alpha-dev",
      "database_id": "replace-with-alpha-dev-d1-id",
      "preview_database_id": "centaur-tenant-alpha-local"
    },
    {
      "binding": "TENANT_DB_BRAVO",
      "database_name": "centaur-tenant-bravo-dev",
      "database_id": "replace-with-bravo-dev-d1-id",
      "preview_database_id": "centaur-tenant-bravo-local"
    }
  ],
  "durable_objects": {
    "bindings": [
      { "name": "TENANT_DO", "class_name": "TenantDO" },
      { "name": "SESSION_DO", "class_name": "SessionDO" }
    ]
  }
}
```

Local commands:

```bash
pnpm wrangler d1 create centaur-control-dev
pnpm wrangler d1 migrations create centaur-control-dev init
pnpm wrangler d1 migrations apply centaur-control-dev --local
pnpm wrangler d1 execute centaur-control-dev --local --file ./seeds/dev.sql
pnpm wrangler dev --persist-to .wrangler/local-state
```

Use `--local` for local D1 data and `--remote` only for explicit staging or
production operations. Local state should live under `.wrangler/state` or a
project-specific path such as `.wrangler/local-state`; keep those paths in
`.gitignore`.

Tenant database modes:

| Mode | Local approach |
| --- | --- |
| Pooled default | One `CONTROL_DB`, seeded with multiple tenants |
| Dedicated tenant simulation | Fixed local bindings such as `TENANT_DB_ALPHA` and `TENANT_DB_BRAVO` |
| Unit tests | Thin repository tests may use plain SQLite fixtures |
| Integration tests | Miniflare or `wrangler dev` must exercise real D1 bindings |

Tenant DB resolution should stay behind a boundary:

```ts
type TenantDatabaseRef =
  | { kind: "pooled"; tenantId: TenantId; binding: "CONTROL_DB" }
  | { kind: "dedicated"; tenantId: TenantId; binding: TenantD1Binding };
```

Local seed data should create at least two merchants, Slack installs, principals,
teams, direct and delegate memberships, roles, tool grants, secrets, sessions,
resource bindings, quotas, and DB aliases.
Cross-tenant denial tests should use those fixtures.

Local resource notes:

- D1 migrations and seed SQL run with Wrangler `--local`.
- R2 fixture files can be uploaded with Wrangler `r2 object put --local`.
- Durable Object state is initialized through development endpoints or tests
  that call the object, since Durable Objects do not have a seed CLI.
- Queues and Workflows run locally through Wrangler-backed development sessions.
- Container development should use local Dockerfile builds where possible, with
  registry image references only when needed.
- Remote bindings are useful for staging investigations, with explicit config
  and review because remote writes affect real resources.

The raw DB shim should also run locally. Use a fake Postgres server for unit
tests and a Docker Postgres instance for integration tests that exercise pgwire,
lease validation, gateway policy, and timeout behavior.

## Implementation Phases

| Phase | Focus | Deliverable |
| --- | --- | --- |
| 0 | Fork boundary and compatibility audit | Identify reusable Centaur pieces and replacement targets |
| 1 | Dependency simplification | Remove Kubernetes/Rails/Postgres-control-plane assumptions from the design boundary |
| 2 | Domain types and boundaries | Tenant, principal, session, secret, grant, egress, DB lease, quota, and resource-binding types |
| 3 | Local development foundation | Wrangler config, local D1 migrations, seeds, fixture tenants, Miniflare tests |
| 4 | Slack ingress and sessions | Slack verification, tenant mapping, Tenant and Session Durable Objects |
| 5 | Container runner | Codex/Claude harness container, prompts, artifacts, cancellation |
| 6 | Secret Broker and vault | Own-vault metadata, encrypted payloads, 1Password adapters |
| 7 | HTTP/HTTPS egress | Container outbound handler, host allowlists, credential transforms |
| 8 | Tool Gateway | Typed merchant tools, grants, approvals, idempotency |
| 9 | Slack commerce operations | Block Kit actions, modals, imports, App Home, Work Objects |
| 10 | Raw database access | SQL tool, Postgres shim, DB Gateway, leases, private connectivity spike |
| 11 | Admin console | Tenants, installs, grants, secrets, DB access, audit |
| 12 | Production hardening | Isolation tiers, quotas, abuse controls, cost accounting, DR, canary tenants |

## Validation Plan

Run broader checks when touching tenant isolation, auth, signing, secret
resolution, egress policy, raw DB sessions, D1 schema, Queues, or Durable Object
lifecycle. Low-risk documentation and wiring changes need lightweight checks.

Type and boundary checks:

- Type fixtures for invalid tenant, session, secret, grant, and lifecycle
  states.
- Type fixtures for invalid quota, resource binding, and tenant tier states.
- Unit tests for Slack event parsers and interaction payload parsers.
- Unit tests for `ThreadKey` parsing.
- Unit tests for grant resolution.
- Unit tests for egress transform matching.

Integration checks:

- Fake OpenAI, Anthropic, and GitHub endpoints for egress transforms.
- Local D1 migration and seed flow.
- Dedicated tenant simulation with multiple D1 bindings.
- Cross-tenant D1 repository denial.
- Cross-tenant R2 key denial.
- Cross-tenant search filter denial.
- Cross-tenant egress denial.
- Tenant quota denial for sessions, containers, raw DB leases, and tool spend.
- CSV upload preview and approval.
- Idempotent refund and cancel actions.
- DB lease expiry.
- Container shim to fake Postgres server.
- Docker Postgres integration path for raw DB gateway behavior.
- Queue replay and idempotency.

Security checks:

- Secret readback denial.
- Tenant ID required for every repository access path.
- Tenant context required before Durable Object, Workflow, Queue, R2, and search
  calls.
- Audit events omit secret values and raw auth material.
- Raw DB sessions default to readonly roles and short leases.

Dependency checks:

- No Kubernetes, Helm, or Pod assumptions in Cloudflare runtime paths.
- No Rails runtime dependency for the admin console.
- No Postgres dependency for platform control-plane metadata.
- No long-lived compatibility bridge required for the default happy path.

## Open Questions

- Which merchant database providers must be supported first?
- How many tenants need raw DB access on day one?
- Should raw DB sessions start as readonly-only?
- Which tenants need dedicated data resources at launch?
- Will merchants upload custom code, or will all extensions stay as platform
  typed tools?
- Which harnesses can cleanly route model calls through a Model Gateway?
- Do we need per-merchant Slack apps for enterprise customers?
- What private network path should be promised for raw TCP database access?
- Which tools require a temporary iron-proxy container bridge?
- What retention window is required for full transcripts and audit payloads?

## References

Cloudflare:

- Containers: https://developers.cloudflare.com/containers/
- Container outbound traffic: https://developers.cloudflare.com/containers/platform-details/outbound-traffic/
- Durable Objects: https://developers.cloudflare.com/durable-objects/
- Durable Objects best practices: https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- Sandbox SDK: https://developers.cloudflare.com/sandbox/
- Workers for Platforms: https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/
- Workers for Platforms resource isolation: https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/bindings/
- Workers for Platforms outbound workers: https://developers.cloudflare.com/cloudflare-for-platforms/workers-for-platforms/configuration/outbound-workers/
- Workers TCP sockets: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- Hyperdrive: https://developers.cloudflare.com/hyperdrive/
- Hyperdrive private databases: https://developers.cloudflare.com/hyperdrive/configuration/connect-to-private-database/
- D1: https://developers.cloudflare.com/d1/
- D1 local development: https://developers.cloudflare.com/d1/best-practices/local-development/
- Workers local data: https://developers.cloudflare.com/workers/local-development/local-data/
- R2: https://developers.cloudflare.com/r2/
- Queues: https://developers.cloudflare.com/queues/
- Queues local development: https://developers.cloudflare.com/queues/configuration/local-development/
- Workflows: https://developers.cloudflare.com/workflows/
- Workflows local development: https://developers.cloudflare.com/workflows/build/local-development/
- Workflows limits: https://developers.cloudflare.com/workflows/reference/limits/
- Containers local development: https://developers.cloudflare.com/containers/local-dev/
- Secrets Store: https://developers.cloudflare.com/secrets-store/

Upstream project:

- Centaur: https://github.com/paradigmxyz/centaur

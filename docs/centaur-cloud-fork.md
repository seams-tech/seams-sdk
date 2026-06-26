# Cloudflare-Native Centaur Fork Plan

Last reviewed: 2026-06-26

This document captures the target architecture for a Cloudflare-native fork of
[paradigmxyz/centaur](https://github.com/paradigmxyz/centaur) for a
multi-tenant merchant platform. The goal is to preserve Centaur's useful
interaction model while replacing the Kubernetes production substrate with
Cloudflare Workers, Durable Objects, Containers, D1, R2, Queues, Workflows,
Hyperdrive, and Worker-side secret brokerage.

## Goals

- Run one multi-tenant platform for many merchants.
- Avoid Kubernetes and cluster operations.
- Keep the primary user experience in existing UIs: Slack, Codex, Claude, and
  similar agent surfaces.
- Provide one agent instance per merchant workspace, project, or configured
  tenant boundary.
- Allow multiple Slack users to collaborate with the same agent session through
  the same Slack thread.
- Keep merchant credentials out of agent containers.
- Support both typed merchant tools and privileged raw database sessions.
- Support 1Password and a cheaper first-party secret vault through the same
  `SecretRef` model.

## Existing Centaur Behavior To Preserve

Centaur is primarily a Slack/API agent control plane. Its "multiplayer" behavior
comes from Slack thread sharing: once a bot is mentioned, the thread maps to a
durable session, and multiple Slack members in that thread can add messages to
the same session. Thread visibility inherits Slack visibility. A public channel
thread is effectively visible to channel members; a private channel thread is
limited by Slack's private-channel membership.

Centaur has an operator console for credentials, principals, roles, grants, and
admin state. That console is an operations surface. Slack remains the default
conversation UI.

Upstream production Centaur uses Postgres, Kubernetes sandbox pods, and
iron-proxy for outbound credential substitution. The Cloudflare fork should keep
the security contract and replace the substrate.

## Target Architecture

```text
Slack / API clients
   |
Ingress Worker
   |
Tenant Resolver
   |
Session Durable Object
   |
Queues / Workflows
   |
Agent Container Durable Object
   |
Cloudflare Container / Sandbox SDK
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

Core Cloudflare products:

- **Workers** for ingress, APIs, tool execution, egress gateways, model
  gateways, secret brokerage, and Slack delivery.
- **Durable Objects** for per-session state, active-run coordination, WebSocket
  fanout, cancellation, and container ownership.
- **Cloudflare Containers / Sandbox SDK** for running Codex, Claude Code, and
  other agent harnesses.
- **D1** for tenant registry, Slack installs, principals, grants, sessions,
  executions, and audit indexes.
- **R2** for transcripts, artifacts, uploaded files, large logs, and encrypted
  secret blobs when the first-party vault stores payloads outside D1.
- **Queues** for run dispatch, Slack delivery retries, audit fanout, and
  background tool jobs.
- **Workflows** for long-running merchant automations, scheduled checks, waits,
  approvals, and retryable multi-step jobs.
- **Hyperdrive** for Worker-executed SQL paths against known Postgres/MySQL
  databases where pooling and caching are useful.
- **Secrets Store / Worker secrets** for platform root material and bootstrap
  secrets. Merchant secrets should live in the first-party vault or 1Password
  adapter, with only wrapping/bootstrap keys in Cloudflare secret bindings.

Cloudflare docs that affect this architecture:

- Containers: https://developers.cloudflare.com/containers/
- Container outbound traffic: https://developers.cloudflare.com/containers/platform-details/outbound-traffic/
- Durable Objects: https://developers.cloudflare.com/durable-objects/
- Sandbox SDK: https://developers.cloudflare.com/sandbox/
- Workers TCP sockets: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
- Hyperdrive: https://developers.cloudflare.com/hyperdrive/
- Hyperdrive private databases: https://developers.cloudflare.com/hyperdrive/configuration/connect-to-private-database/
- D1: https://developers.cloudflare.com/d1/
- R2: https://developers.cloudflare.com/r2/
- Queues: https://developers.cloudflare.com/queues/
- Workflows: https://developers.cloudflare.com/workflows/
- Secrets Store: https://developers.cloudflare.com/secrets-store/

## Tenant Model

Every internal request must carry a parsed `TenantContext`.

```text
tenant:{tenant_id}:slack:{team_id}:{channel_id}:{thread_ts}
tenant:{tenant_id}:api:{client_id}:{session_id}
tenant:{tenant_id}:codex:{workspace_id}:{session_id}
```

The ingress boundary validates and normalizes raw external identifiers once:

- Slack `team_id`, `channel_id`, `thread_ts`, `user_id`
- API key and OAuth subject
- Merchant workspace/project identifiers
- Installed Slack app metadata
- Agent session IDs

Core logic should never accept raw Slack event objects, raw DB rows, partial
tenant objects, or optional identity fields. D1 has no row-level security, so
tenant isolation must be enforced through narrow repository functions and
type-level boundaries.

Suggested internal shape:

```ts
type TenantContext = {
  kind: "tenant_context";
  tenantId: TenantId;
  plan: TenantPlan;
  status: TenantStatus;
};

type Principal =
  | { kind: "slack_user"; tenantId: TenantId; teamId: SlackTeamId; userId: SlackUserId }
  | { kind: "slack_channel"; tenantId: TenantId; teamId: SlackTeamId; channelId: SlackChannelId }
  | { kind: "api_client"; tenantId: TenantId; clientId: ApiClientId }
  | { kind: "system"; tenantId: TenantId; actor: SystemActor };
```

The important invariant is that `tenantId` is required on every branch. There
should be no optional identity, auth, lifecycle, signing, budget, or session
fields in core types.

## Slack Install Model

Use one platform Slack app installed into each merchant workspace.

- A shared Slack signing secret verifies events for the platform app.
- Each Slack workspace installation produces a merchant-specific bot token.
- The bot token is stored as a secret reference, encrypted in the vault.
- Slack `team_id` resolves to one or more tenant install records.
- If one Slack workspace hosts multiple merchants, channel-level or app-home
  configuration resolves the final tenant.

This keeps merchant onboarding simple and makes event verification deterministic.
Per-merchant Slack apps can be added later for enterprise isolation, with a
separate signing-secret lookup at the request boundary.

## Session Durable Object

One Session Durable Object owns each chat thread or API session.

Responsibilities:

- Serialize user messages into the session transcript.
- Enforce one active run or a clear queued-run lifecycle.
- Track active execution, cancellation, and final delivery state.
- Fan out streamed events to Slack delivery, web clients, and audit sinks.
- Store compact session state locally and persist durable state to D1/R2.
- Start runner work through Queues.

Lifecycle should be a discriminated union:

```ts
type SessionLifecycle =
  | { kind: "idle"; tenantId: TenantId; sessionId: SessionId }
  | { kind: "queued"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId }
  | { kind: "running"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId; runnerId: RunnerId }
  | { kind: "cancelling"; tenantId: TenantId; sessionId: SessionId; executionId: ExecutionId; requestedBy: Principal }
  | { kind: "terminal"; tenantId: TenantId; sessionId: SessionId; terminal: TerminalState };
```

Functions that mutate lifecycle should accept the narrowest valid branch. For
example, `startExecution` should accept `SessionLifecycle & { kind: "queued" }`
rather than a broad session object.

## Runner And Container Model

Use Cloudflare Containers through a container-owning Durable Object. The Sandbox
SDK can be used where its file/command API fits the desired runner surface.

Container identity:

```text
container_id = tenant:{tenant_id}:session:{session_id}:runner:{runner_id}
```

Default runner behavior:

- Start one container per active run or warm session.
- Mount no merchant credentials.
- Provide transcript files, prompt files, working directory state, and tool
  catalog config.
- Provide placeholder environment variables for model/tool clients that require
  API-key-looking values.
- Route HTTP/HTTPS egress through Cloudflare container outbound handlers.
- Route raw DB sessions through the local DB shim described below.
- Persist outputs and artifacts to R2.
- Destroy idle temporary sandboxes aggressively; keep only explicit warm
  sessions alive.

Codex and Claude Code should run as harnesses inside the container. Where a
harness supports a custom model base URL, route it through a Model Gateway.
Where a harness expects direct vendor calls, use egress transforms with
placeholder values.

## Iron-Proxy Replacement

The target fork should model iron-proxy as a trusted egress plane implemented in
Cloudflare Workers and container outbound handlers.

Use Cloudflare-native egress for new work. Reserve an iron-proxy container for
short-lived migration tests and specific upstream tools that still depend on
`HTTPS_PROXY` semantics.

### HTTP And HTTPS Egress

Container settings:

```text
enableInternet = false
interceptHttps = true
allowedHosts = policy-derived allowlist
```

The outbound handler has access to Worker bindings and can:

- Deny unknown hosts.
- Match host, method, path, headers, and query params.
- Resolve the current container to tenant, session, and principal.
- Load the effective egress policy.
- Resolve secrets from Secret Broker.
- Inject headers, query params, bearer tokens, OAuth tokens, GCP tokens, and
  AWS SigV4 signatures.
- Replace placeholder values in approved request locations.
- Emit an audit event before forwarding.

Centaur fragment concepts map into the Cloudflare-native model:

```text
iron-control principal      -> tenant/principal/grant rows
proxy id                    -> container_id / session_id
proxy sync                  -> egress_policy_revision
secret source               -> SecretRef
replace.proxy_value         -> placeholder replacement rule
inject.header/query         -> request rewrite rule
rules.host                  -> host allowlist rule
proxy audit                 -> audit_events + Workers logs + R2 trail
```

Suggested internal transform type:

```ts
type EgressTransform =
  | { kind: "inject_header"; host: HostPattern; header: HeaderName; secret: SecretRef; formatter: Formatter }
  | { kind: "replace_header_placeholder"; host: HostPattern; header: HeaderName; placeholder: SecretPlaceholder; secret: SecretRef }
  | { kind: "inject_query"; host: HostPattern; param: QueryParam; secret: SecretRef }
  | { kind: "oauth_bearer"; host: HostPattern; credential: OAuthCredentialRef; scopes: OAuthScopeSet }
  | { kind: "gcp_auth"; host: HostPattern; serviceAccount: SecretRef; scopes: OAuthScopeSet }
  | { kind: "aws_sigv4"; host: HostPattern; service: AwsService; region: AwsRegion; credential: AwsCredentialRef };
```

### Native Egress Versus Iron-Proxy Container

Native egress is the preferred target:

- Fewer long-running moving parts.
- Direct access to Worker bindings.
- Cleaner tenant policy checks.
- Lower operational surface.
- Better fit for Cloudflare's container model.

The iron-proxy container bridge is useful for:

- Proving compatibility with upstream Centaur tools.
- Keeping `HTTPS_PROXY`-dependent clients working during the port.
- Testing existing transform fragments before translating them.
- Supporting `pg_dsn` temporarily while the DB Gateway is implemented.

The bridge should be time-boxed. It recreates a Kubernetes-shaped sidecar model
inside Cloudflare and adds another container lifecycle to manage.

## Tool Gateway

Typed tools should be the default merchant capability surface.

Examples:

```text
shopify.orders.search
shopify.orders.refund
shopify.inventory.adjust
stripe.refunds.create
merchant.customers.lookup
merchant.reports.run_sql_readonly
```

The container calls tools over HTTPS or an internal service route. The Tool
Gateway performs:

- Tenant resolution.
- Principal and channel grant checks.
- Tool allowlist checks.
- Secret resolution.
- Approval gating for sensitive actions.
- Spend, rate, and budget enforcement.
- Idempotency and retries.
- Structured audit logging.

Merchant credentials should flow only into Tool Gateway calls. They should not
be injected into the container environment.

## Slack Commerce Operations

Slack can host a meaningful amount of product, inventory, and order management
without becoming a full Shopify Admin clone. Use Slack for high-frequency
operations, approvals, exception handling, lightweight edits, and bulk import
review. Keep deep catalog management, complex filtering, and long-running admin
screens in the merchant web console.

Slack primitives to use:

- **Block Kit messages** for product cards, order cards, status summaries,
  action buttons, select menus, and overflow menus.
- **Modals** for focused forms such as create product, edit SKU, adjust
  inventory, refund order, cancel order, and fulfill shipment.
- **File input** for CSV product imports, bulk inventory updates, and image
  attachments.
- **Data table blocks** for compact product, inventory, and order result sets
  with pagination, sorting, filtering, and clickable cells.
- **Work Objects and flexpanes** for product, order, customer, and inventory
  entities that need a richer right-side detail view inside Slack.
- **App Home** for a persistent merchant dashboard: low-stock queues, pending
  approvals, failed imports, recent orders, saved filters, and onboarding.
- **Workflow Builder custom steps** for recurring merchant automations such as
  daily inventory review, order exception triage, and approval routing.

### Product Listing Uploads

CSV import flow:

```text
merchant uploads CSV in Slack
  -> Slack file event / modal file input
  -> Tool Gateway downloads file with Slack bot token
  -> Import Worker stores raw file in R2
  -> parser validates rows and normalizes product drafts
  -> agent posts preview data table + error summary
  -> merchant confirms import
  -> Tool Gateway writes products through Shopify/commerce adapter
  -> final Slack report links to import artifact and changed products
```

Use R2 for raw uploads, parsed previews, and error reports. Use D1 for import
jobs, row counts, validation status, user approvals, and final write results.

The agent should never write a bulk import directly from a file upload. It
should always post a preview and require an explicit confirmation from a
principal with the right merchant role.

Suggested import lifecycle:

```ts
type ProductImportLifecycle =
  | { kind: "uploaded"; tenantId: TenantId; importId: ImportId; uploadedBy: Principal; fileRef: R2ObjectRef }
  | { kind: "validating"; tenantId: TenantId; importId: ImportId; fileRef: R2ObjectRef }
  | { kind: "needs_review"; tenantId: TenantId; importId: ImportId; previewRef: R2ObjectRef; errorCount: number }
  | { kind: "approved"; tenantId: TenantId; importId: ImportId; approvedBy: Principal; approvalId: ApprovalId }
  | { kind: "applying"; tenantId: TenantId; importId: ImportId; executionId: ExecutionId }
  | { kind: "completed"; tenantId: TenantId; importId: ImportId; resultRef: R2ObjectRef }
  | { kind: "failed"; tenantId: TenantId; importId: ImportId; errorRef: R2ObjectRef };
```

### Inventory Management

Slack should handle inventory by exception and confirmation:

- App Home shows low-stock SKUs, oversold SKUs, stale counts, and locations that
  need review.
- A channel message posts daily or event-driven inventory exceptions.
- A data table summarizes SKUs, location, available quantity, committed
  quantity, incoming quantity, and recommended action.
- Row-level actions open modals for adjustment, transfer, reorder note, or
  ignore.
- High-risk adjustments require approval in the Slack thread before execution.

Inventory actions should go through typed tools:

```text
inventory.search
inventory.adjust
inventory.transfer
inventory.reserve
inventory.release_reservation
inventory.low_stock_report
```

The typed tools must enforce location scope, SKU scope, quantity limits, and
approval policy. The Slack UI should display the resulting operation ID and
final state after the tool commits.

### Order Management

Slack is a good fit for order triage:

- New high-value order notifications.
- Failed payment or fraud-review notifications.
- Fulfillment exceptions.
- Refund/cancel approval requests.
- Customer-support escalations.

Order cards should include concise state and actions:

```text
Order #1042
Customer: Ada Lovelace
Status: paid, unfulfilled
Risk: low
Total: $248.00
Actions: View, Fulfill, Refund, Cancel, Add note
```

Actions that mutate money, fulfillment, or customer-visible state should open a
modal that collects the exact fields needed and then posts a confirmation
message before applying the change.

Order tools:

```text
orders.search
orders.get
orders.fulfill
orders.refund
orders.cancel
orders.add_note
orders.flag_for_review
```

Refunds and cancellations should include idempotency keys tied to the Slack
interaction payload and execution ID. The final Slack message should include the
merchant platform result, provider result, and audit event ID.

### Product And Order Work Objects

Use Slack Work Objects when a product, order, or customer is referenced often
in Slack.

Work Object candidates:

- Product
- Variant/SKU
- Inventory item
- Order
- Customer
- Return/refund request
- Import job

The unfurl should show safe summary fields for everyone in the conversation.
The flexpane can show richer authenticated details and edit actions. Sensitive
fields should require user-level auth or role checks before rendering in the
flexpane.

### App Home Merchant Dashboard

App Home should be the persistent operations dashboard:

- Store connection status.
- Pending approvals.
- Recent failed automations.
- Low-stock queue.
- Order exception queue.
- Bulk import queue.
- Saved searches and common actions.

App Home views are per-user, so the backend should render them from the user's
principal, roles, and grants. Avoid putting cross-tenant state or privileged
admin actions into a shared channel message.

### Slack UX Boundaries

Use Slack for:

- Approvals.
- Exception queues.
- Small result sets.
- Single-entity edits.
- Bulk import review.
- Conversational agent commands.
- Notifications that need human action.

Use the web console for:

- Large catalog browsing.
- Complex variant editing.
- Drag-and-drop media management.
- Deep filtering and analytics.
- Long-running configuration.
- Merchant onboarding that needs many screens.

This split keeps Slack fast and operational while preserving a richer admin UI
where dense workflows need it.

## Raw Database Access

Typed tools are sufficient for common merchant operations. Raw DB access is
still valuable for developer-style agents: schema inspection, migrations,
`psql`, ORM CLIs, application debugging, data repair, and tests that expect a
normal `DATABASE_URL`.

Cloudflare Containers outbound handlers intercept HTTP and HTTPS. They do not
intercept arbitrary non-HTTP ports such as Postgres `5432`. Workers can open
outbound TCP sockets. Hyperdrive supports Worker access to Postgres/MySQL with
pooling and caching for known database paths.

Support three database modes:

| Mode | Default audience | Implementation |
| --- | --- | --- |
| Typed tools | Merchant operations | Tool Gateway over HTTPS |
| SQL tool | Controlled ad hoc SQL | Worker executes SQL through a driver, Hyperdrive, or TCP |
| Raw DB session | Developer agents and privileged ops | Local container shim to DB Gateway |

### Raw DB Session Design

```text
agent / psql / ORM
  -> localhost:15432 inside container
  -> pgwire shim
  -> WebSocket over HTTPS to db.internal
  -> DB Gateway Worker
  -> Workers TCP socket
  -> merchant Postgres
```

For MySQL:

```text
agent / mysql client / ORM
  -> localhost:13306 inside container
  -> mysql wire shim
  -> WebSocket over HTTPS to db.internal
  -> DB Gateway Worker
  -> Workers TCP socket
  -> merchant MySQL
```

The container receives a fake local DSN:

```text
DATABASE_URL=postgresql://centaur:lease@127.0.0.1:15432/app
```

The real DSN stays in Secret Broker. The DB Gateway validates:

- Tenant ID.
- Session ID.
- Principal.
- Database alias.
- Lease ID and expiry.
- Allowed protocol.
- Allowed database and schema.
- Readonly/write/migration mode.
- Connection and transaction limits.
- Budget.
- Approval state.

Enforcement should rely on database roles and gateway limits:

- Readonly role by default.
- Schema-specific grants.
- `statement_timeout`.
- `idle_in_transaction_session_timeout`.
- Connection limits.
- No superuser.
- No broad DDL except explicit migration grants.
- Short leases.

The gateway should log connection metadata, byte counts, duration, database
alias, principal, lease, and policy decision. SQL-text auditing is useful for
simple query modes, but correctness should rely on database-native roles and
gateway connection control rather than universal protocol parsing.

### Hyperdrive Use

Use Hyperdrive for Worker-executed SQL paths against stable, known Postgres or
MySQL databases where pooling matters. This fits the SQL tool and reports.

Use direct Worker TCP sockets for raw byte-forwarded DB sessions. The raw
session bridge transports database wire bytes and needs socket-level forwarding.
Hyperdrive is a higher-level Worker database connection path through ordinary
drivers.

For private merchant databases, prefer Cloudflare's private connectivity path
where available. Hyperdrive documents private database connectivity through
Workers VPC or Cloudflare Tunnel. Raw TCP session support for private networks
needs a concrete platform verification spike before committing to a customer
promise.

## Secret Broker

Make the first-party vault the primary runtime abstraction. Add 1Password as an
adapter.

Suggested `SecretRef` model:

```ts
type SecretBackend =
  | { kind: "own_vault"; tenantId: TenantId; secretId: SecretId }
  | { kind: "onepassword_connect"; tenantId: TenantId; vault: OnePasswordVault; item: OnePasswordItem; field: OnePasswordField }
  | { kind: "onepassword_sync"; tenantId: TenantId; syncedSecretId: SecretId };

type SecretRef = {
  kind: "secret_ref";
  tenantId: TenantId;
  backend: SecretBackend;
  scope: SecretScope;
};
```

Own vault design:

- D1 stores metadata: `tenant_id`, `secret_id`, backend kind, status, labels,
  grants, rotation state, and audit indexes.
- R2 or D1 stores encrypted secret blobs.
- Cloudflare Secrets Store or Worker secrets hold platform bootstrap and
  wrapping-key material.
- Secret Broker decrypts only inside trusted Worker code.
- Per-tenant data keys limit blast radius.
- Secret values are never returned to admin UI callers.

1Password support:

- `onepassword_connect` resolves live through 1Password Connect where customers
  already operate it.
- `onepassword_sync` imports or syncs selected 1Password items into the
  first-party vault for cheaper runtime reads.
- Service-account based automation can seed or rotate values, with runtime
  still reading the first-party vault when cost and latency matter.

## Data Model Sketch

Core D1 tables:

```text
tenants(id, slug, plan, status, created_at)
slack_installs(tenant_id, team_id, bot_token_secret_ref, scopes, installed_by)
principals(tenant_id, principal_id, kind, foreign_id, display_name)
roles(tenant_id, role_id, name)
principal_roles(tenant_id, principal_id, role_id)
secrets(tenant_id, secret_id, backend_kind, ref, encrypted_blob_ref, labels, status)
grants(tenant_id, grant_id, grantee_kind, grantee_id, resource_kind, resource_id, policy_json)
sessions(tenant_id, session_id, thread_key, source, lifecycle, active_execution_id, created_at)
messages(tenant_id, session_id, message_id, role, author_principal_id, parts_ref, created_at)
executions(tenant_id, execution_id, session_id, status, runner_id, started_at, completed_at)
events(tenant_id, session_id, event_id, execution_id, type, payload_ref, created_at)
db_leases(tenant_id, lease_id, principal_id, db_alias, mode, expires_at, policy_json)
audit_events(tenant_id, audit_id, actor_principal_id, action, resource, decision, metadata_ref, created_at)
```

Every primary access path must include `tenant_id`. R2 keys should use the same
shape:

```text
tenants/{tenant_id}/sessions/{session_id}/...
tenants/{tenant_id}/executions/{execution_id}/...
tenants/{tenant_id}/audit/{date}/{audit_id}.json
```

## Admin Console

Build a small Cloudflare Pages/Workers admin console for operators and merchant
admins.

Console responsibilities:

- Tenant creation and status.
- Slack install and reinstall flow.
- Principal discovery and role assignment.
- Tool grants.
- Secret references and vault sync.
- DB aliases, DB leases, and raw DB access approvals.
- Audit search.
- Usage and cost reporting.

The console should avoid becoming an agent chat UI. Slack and existing agent
apps stay as the interaction surfaces.

## Observability And Audit

Emit structured audit events for:

- Slack ingress events.
- Session lifecycle transitions.
- Agent execution start/finish/cancel.
- Tool calls and policy decisions.
- Secret access decisions.
- HTTP egress decisions and transforms.
- DB lease creation.
- DB connection open/close.
- Raw DB session byte counts and duration.
- Admin console changes.

Use Workers logs for near-real-time debugging, D1 for indexed audit metadata,
and R2 for full payloads and large artifacts.

Avoid logging:

- Secret values.
- Raw Authorization headers.
- Full OAuth tokens.
- Raw database passwords.
- Customer PII unless the event type explicitly requires it.

## Implementation Phases

### Phase 0: Fork Boundary And Compatibility Audit

- Fork Centaur and identify the smallest reusable pieces: Slack event model,
  session semantics, tool manifests, prompts, and harness integration.
- Mark Kubernetes, Helm, Pod, NetworkPolicy, and Postgres-control-plane paths as
  replacement targets.
- Inventory iron-proxy fragments and translate the useful transform schema into
  Cloudflare-native egress policies.
- Decide which upstream tools need temporary bridge support.

### Phase 1: Domain Types And Boundaries

- Define `TenantContext`, `ThreadKey`, `SessionLifecycle`, `Principal`,
  `SecretRef`, `Grant`, `EgressPolicy`, `DbLease`, and `RunnerLifecycle` as
  discriminated unions.
- Add boundary parsers for Slack events, API keys, D1 rows, Queue messages, and
  container status.
- Add `@ts-expect-error` type fixtures for invalid tenant/session/auth states.
- Add exhaustive `switch` checks with `assertNever`.

### Phase 2: Slack Ingress And Session Durable Object

- Implement Slack signature verification.
- Map Slack install to tenant.
- Normalize Slack thread events into `ThreadKey`.
- Persist messages and session lifecycle.
- Create the Session Durable Object active-run lock.
- Implement Slack final delivery and retry.

### Phase 3: Container Runner

- Build an Agent Container image with Codex/Claude harness support.
- Add prompt and transcript file layout.
- Add placeholder env generation.
- Route runs through Queues.
- Stream output back to Session Durable Object.
- Persist artifacts to R2.
- Add cancellation and timeout handling.

### Phase 4: Secret Broker And Vault

- Implement own-vault metadata and encrypted payload storage.
- Add 1Password Connect live resolver.
- Add 1Password sync/import resolver.
- Implement grants and effective access resolution.
- Add audit events for secret resolution decisions.

### Phase 5: Cloudflare-Native HTTP Egress

- Add container outbound handler.
- Translate Centaur HTTP secret fragments into `EgressTransform`.
- Enforce host allowlists and placeholder replacement.
- Support OpenAI, Anthropic, GitHub, Slack, Shopify, Stripe, OAuth bearer,
  GCP auth, and AWS SigV4 as first targets.
- Add egress audit events.

### Phase 6: Tool Gateway

- Build typed tool registration.
- Add merchant tools for e-commerce workflows.
- Add approval policies for destructive actions.
- Add idempotency keys and replay-safe execution.
- Add per-tenant rate, spend, and budget controls.

### Phase 7: Slack Commerce Operations

- Build product, inventory, order, import, and approval Block Kit components.
- Add modal flows for product edits, inventory adjustments, fulfillment,
  refunds, cancellations, and import approval.
- Add CSV upload ingestion through Slack file events and modal file input.
- Add data table previews for imports, inventory queues, and order searches.
- Add App Home dashboard rendering from principal roles and grants.
- Add Work Object unfurls and flexpanes for products, orders, customers,
  inventory items, and import jobs.
- Add typed commerce tools behind every Slack action.

### Phase 8: Raw Database Access

- Build readonly SQL tool first.
- Implement Postgres local shim in the container.
- Implement DB Gateway WebSocket transport.
- Add Worker TCP socket forwarding for Postgres.
- Add DB lease creation and approval flow.
- Add database role guidance and setup docs.
- Add MySQL after Postgres proves stable.
- Verify private database connectivity options before customer rollout.

### Phase 9: Admin Console

- Build tenant, Slack install, grants, secrets, and DB alias screens.
- Add audit search.
- Add secret value write paths with no secret readback.
- Add 1Password sync status.

### Phase 10: Production Hardening

- Add per-tenant quotas.
- Add abuse controls.
- Add cost accounting.
- Add incident audit export.
- Add disaster recovery procedures for D1/R2.
- Add canary tenants and rollout controls.

## Validation Plan

Low-risk documentation and wiring changes need lightweight checks only.

Run broader checks when touching:

- Tenant isolation.
- Auth and signing.
- Secret resolution.
- Egress policy.
- Raw DB sessions.
- D1 schema.
- Queue or Durable Object lifecycle.

Targeted checks:

- Type fixtures for invalid tenant/session/secret states.
- Unit tests for Slack event parsers.
- Unit tests for `ThreadKey` parsing.
- Unit tests for grant resolution.
- Unit tests for egress transform matching.
- Unit tests for Slack interaction payload parsers.
- Unit tests for product import lifecycle transitions.
- Integration test with fake OpenAI/Anthropic/GitHub endpoints.
- Integration test for cross-tenant egress denial.
- Integration test for CSV upload preview and approval.
- Integration test for idempotent refund/cancel actions.
- Integration test for DB lease expiry.
- Integration test for container shim to fake Postgres server.
- Replay tests for Queue idempotency.

## Key Decisions

1. Use Slack as the primary multiplayer UI.
2. Keep the console focused on credentials, grants, tenants, audit, and ops.
3. Use Cloudflare-native egress as the target iron-proxy replacement.
4. Keep an iron-proxy container bridge only for migration compatibility.
5. Use typed tools for merchant operations.
6. Add raw DB sessions as a privileged developer/ops capability.
7. Keep merchant credentials in Worker-side trusted services.
8. Make the first-party vault primary and 1Password an adapter.
9. Require tenant identity in every core domain object.
10. Treat D1 row filtering as an application invariant enforced by narrow
    repositories and type-level boundaries.

## Open Questions

- Which merchant database providers must be supported first?
- How many tenants need raw DB access on day one?
- Should raw DB sessions start as readonly-only?
- Which harnesses can cleanly route model calls through a Model Gateway?
- Do we need per-merchant Slack apps for enterprise customers?
- What private network path should be promised for raw TCP database access?
- Which tools require a temporary iron-proxy container bridge?
- What retention window is required for full transcripts and audit payloads?

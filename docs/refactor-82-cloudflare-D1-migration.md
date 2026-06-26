# Cloudflare D1 Migration Plan

Date created: June 26, 2026

Status: design plan. This plan migrates the default Seams control panel and
signer persistence path from local/hosted Postgres to Cloudflare D1 and Durable
Objects, while retaining a first-class Postgres adapter for larger-limit routes.

## Decision

Move console persistence to Cloudflare D1 and make the Cloudflare Worker runtime
the primary server runtime for the dashboard API. Move signer persistence to a
D1 plus Durable Object split:

- D1 owns queryable signer metadata and sealed ciphertext records.
- Durable Objects own per-entity signer coordination, hot counters, reservations,
  presignature pools, and serialized state transitions.

D1 is a Worker binding API, not a TCP database. Local development uses
Wrangler/Miniflare-managed local D1 state. Production uses the same
`D1Database` binding shape exposed through `env`.

The storage boundary supports both D1/DO and Postgres adapters. D1/DO is the
first-release default. Postgres is available through the same domain-store ports
when a tenant or deployment needs larger relational storage limits.

Authoritative Cloudflare references:

- [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/)
- [D1 Worker binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/)
- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)
- [D1 data security](https://developers.cloudflare.com/d1/reference/data-security/)
- [Hyperdrive Postgres connectivity](https://developers.cloudflare.com/hyperdrive/)
- [Durable Object storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/)
- [Durable Object rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [Durable Object migrations](https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/)
- [Workers testing](https://developers.cloudflare.com/workers/testing/)

## Goal

Replace the current direct Postgres-backed console services with adapter-backed
services that support D1/DO by default and Postgres for larger-limit routes:

- org/project/environment configuration
- team RBAC
- approvals, policies, API keys, account settings, and audit events
- wallets and sponsored execution history
- production sponsored EVM gas payments with prepaid billing
- dashboard billing, prepaid balance, and reconciliation views
- runtime snapshots and snapshot outbox dispatch
- console observability where the volume fits D1 limits
- signer metadata, wallet auth records, sealed signer ciphertext, active
  signing coordination, session budgets, idempotency guards, and presignature
  reservation state

The migration should remove Postgres from the default local development path.
Developers should run the dashboard and signer flows against local D1 plus local
SQLite-backed Durable Objects through Wrangler.

## Non-Goals

- preserving direct Postgres service paths after adapter replacement
- maintaining `pg` connection-string flows for console storage
- emulating Postgres RLS, advisory locks, partitions, JSONB operators, or row
  locks in generic wrappers
- keeping the in-memory console services as production-adjacent backends
- migrating high-volume observability into one unbounded D1 table
- building a generic SQL compatibility adapter across D1 and Postgres; storage
  portability is implemented through domain-store adapters
- storing plaintext signer shares, root shares, private keys, KEKs, or API
  secrets in D1 or Durable Object storage

## Current Postgres Coupling

Current console storage relies on Postgres features that D1 does not expose:

- `pg` pool and connection-string bootstrapping in `apps/web-server/src/index.ts`
- tenant transactions and RLS through `withConsoleTenantContextTx`
- migration advisory locks
- `FOR UPDATE` row locks in prepaid reservations
- `FOR UPDATE SKIP LOCKED` in runtime snapshot outbox claiming
- JSONB columns, JSONB predicates, and JSONB type checks
- partial indexes and expression indexes in several console stores
- observability event partitioning by month

These should be replaced with D1-native schemas and operation-specific
conditional writes.

Current signer storage is the non-`console_` side of the split Postgres
database. It includes:

- wallet and wallet-auth records
- WebAuthn authenticators, credential bindings, and challenges
- email OTP challenges, grants, enrollments, recovery escrows, and auth state
- wallet signers and threshold key metadata
- sealed signing-root secret shares
- threshold sessions, session consumption records, and budget reservations
- ECDSA presign sessions and presignature pools
- device-linking sessions, identity links, app-session versions, and recovery
  records

The signer domain should be split by behavior. Durable, queryable metadata moves
to D1. Serialized signer coordination moves to Durable Objects.

## Target Architecture

Use one narrow storage boundary for all console services. The default
Cloudflare adapter uses D1, and the large-limit adapter uses Postgres behind the
same domain-store ports.

The D1 adapter owns this binding shape:

```ts
type ConsoleD1Database = {
  prepare(query: string): ConsoleD1PreparedStatement;
  batch(statements: readonly ConsoleD1PreparedStatement[]): Promise<readonly ConsoleD1Result[]>;
  exec(query: string): Promise<ConsoleD1ExecResult>;
};

type ConsoleD1PreparedStatement = {
  bind(...values: readonly ConsoleD1Value[]): ConsoleD1PreparedStatement;
  first<TRecord extends Record<string, unknown>>(): Promise<TRecord | null>;
  all<TRecord extends Record<string, unknown>>(): Promise<{ results: TRecord[] }>;
  run(): Promise<ConsoleD1Result>;
};
```

Rules:

- Core console logic accepts precise domain records. Adapters keep raw storage
  rows at the boundary.
- Each D1 adapter parses raw rows at the storage boundary.
- Each Postgres adapter parses raw rows at the storage boundary.
- Each write path owns one explicit storage operation shape.
- JSON is stored as `TEXT` and parsed into typed domain objects at read
  boundaries for D1. Postgres adapters may use `JSONB` internally. Core domain
  code still receives parsed domain objects.
- IDs, tenant keys, lifecycle state, billing state, and sponsorship state are
  required fields.
- Invalid lifecycle combinations are modeled with discriminated unions and
  rejected with `@ts-expect-error` type fixtures.

## Storage Backend Adapter

Support D1 and Postgres through domain-level storage adapters. D1 remains the
default first-release backend. Postgres is the larger-limit escape hatch for
tenants or deployments that outgrow D1's per-database cap or need one logical
relational database.

The storage boundary exposes business operations:

```ts
type ConsoleStorageTarget =
  | {
      kind: 'd1';
      binding: D1BindingName;
      database: ConsoleD1Database;
    }
  | {
      kind: 'postgres';
      binding: HyperdriveBindingName;
      pool: ConsolePostgresPool;
      schema: ConsolePostgresSchemaName;
    };

type SignerStorageTarget =
  | {
      kind: 'cloudflare_d1_do';
      metadataBinding: D1BindingName;
      metadata: SignerD1Database;
      thresholdStoreBinding: DurableObjectBindingName;
      thresholdStore: DurableObjectNamespace<ThresholdStoreDurableObject>;
      kekProvider: SignerKekProvider;
    }
  | {
      kind: 'postgres';
      binding: HyperdriveBindingName;
      pool: SignerPostgresPool;
      schema: SignerPostgresSchemaName;
      kekProvider: SignerKekProvider;
    };

type ConsolePrepaidReservationStore = {
  reserve(input: ReservePrepaidBalanceInput): Promise<ReservePrepaidBalanceResult>;
  settle(input: SettlePrepaidReservationInput): Promise<SettlePrepaidReservationResult>;
  release(input: ReleasePrepaidReservationInput): Promise<ReleasePrepaidReservationResult>;
};

type ConsoleRuntimeSnapshotOutboxStore = {
  enqueue(input: EnqueueRuntimeSnapshotEventInput): Promise<EnqueueRuntimeSnapshotEventResult>;
  claim(input: ClaimRuntimeSnapshotEventsInput): Promise<ClaimRuntimeSnapshotEventsResult>;
  markDispatched(input: MarkRuntimeSnapshotEventDispatchedInput): Promise<void>;
};

type TenantStores = {
  tenantRecords: ConsoleTenantRecordStore;
  billing: ConsoleBillingStore;
  runtimeSnapshots: ConsoleRuntimeSnapshotStore;
  signerMetadata: SignerMetadataStore;
  signerCoordination: SignerCoordinationStore;
};

type TenantStoreFactory = {
  createStores(route: TenantStorageRoute): TenantStores;
};
```

Rules:

- First release routes every tenant to D1/DO by default.
- Postgres adapters are first-class backend implementations behind the same
  domain ports.
- Core console, billing, sponsorship, runtime snapshot, and signer logic cannot
  depend on D1 statements, Postgres clients, transaction handles, row locks, DO
  stubs, or raw rows.
- Backend-specific adapters may use native concurrency internally: D1 atomic
  SQLite statements and leases; Postgres transactions, row locks, advisory locks,
  and `SKIP LOCKED`.
- Worker-hosted Postgres access uses Cloudflare Hyperdrive and a Postgres driver.
  Node migration scripts may use a direct Postgres pool.
- Backend selection is resolved by `TenantStorageRoute`, with exactly one
  console target and one signer target for a request.
- First implementation supports two valid backend families only:
  Cloudflare D1/DO for `shared`, `dedicated_tenant`, and `tenant_shard`; and
  Postgres for `postgres_large_tenant`.
- Mixed console/signer backends are invalid route states for runtime routes,
  admin routes, and migration routes.
- Tenant migrations move from one complete backend family to another through
  freeze, export, import, verification, and route activation. Migration tooling
  may inspect source and target stores, while request routes resolve exactly one
  backend family.
- No cross-store transaction is assumed across console and signer resources.
  Workflows that touch both use idempotency keys and reconciliation.
- Migration code between D1 and Postgres lives at persistence/request
  boundaries.
- Old direct Postgres service implementations are deleted after their behavior is
  represented by Postgres adapters and contract tests.
- A Postgres route cannot be activated until every required port in
  `TenantStores` has a Postgres implementation, adapter migrations have run, and
  the shared adapter contract suite passes against that route.

Port contracts to define before implementation:

- `ConsoleTenantRecordStore`: org, project, environment, RBAC, policies,
  approvals, API keys, account settings, wallets, and audit events.
- `ConsoleBillingStore`: prepaid summaries, reservation lifecycle, ledger
  entries, sponsored execution settlement, and reconciliation reads.
- `ConsoleRuntimeSnapshotStore`: snapshot writes, outbox enqueue, lease claim,
  dispatch acknowledgement, and retry visibility.
- `SignerMetadataStore`: wallet auth, WebAuthn, email OTP, threshold key
  metadata, sealed share ciphertext, recovery records, and identity indexes.
- `SignerCoordinationStore`: signing-session use counts, signing budgets,
  replay guards, presignature pools, pool-fill CAS, and signing-root status.

Every port result must be a narrow `Result`-style union. Idempotency conflicts,
insufficient balance, expired reservations, exhausted signing budgets, duplicate
identity, corrupt persisted rows, and missing custody authority are recoverable
domain failures. Driver errors stay inside adapters.

Postgres adapter contract:

- Postgres schemas mirror the D1 logical schema: the same tenant keys, lifecycle
  columns, idempotency keys, uniqueness constraints, and parse boundaries.
- Postgres may use native `BIGINT`, `JSONB`, partial indexes, row locks, and
  `FOR UPDATE SKIP LOCKED` inside the adapter. These features cannot leak into
  domain-store interfaces.
- Billing reserve/settle/release operations run in one transaction and lock the
  summary and reservation rows they mutate.
- Sponsored settlement finalization runs in one transaction that updates the
  sponsored execution, reservation lifecycle, and ledger entry.
- Snapshot outbox claiming may use `FOR UPDATE SKIP LOCKED`. It must return the
  same claim, retry, and dead-letter result unions as the D1 lease adapter.
- Signer metadata and sealed ciphertext use the same required ciphertext,
  digest, AAD, KEK, and audit fields as the D1 adapter.
- Signer coordination uses transactions, row locks, and unique idempotency
  indexes to match the Durable Object RPC result contracts.

## Local Development

Create a local D1 workflow that replaces the local Postgres Docker path.

Wrangler configuration target:

```toml
[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console"
database_id = "<remote-d1-database-id>"
preview_database_id = "seams-console-local"
migrations_dir = "migrations/d1"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer"
database_id = "<remote-signer-d1-database-id>"
preview_database_id = "seams-signer-local"
migrations_dir = "migrations/d1-signer"

[[durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[migrations]]
tag = "signer-do-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]

[[hyperdrive]]
binding = "SEAMS_POSTGRES"
id = "<hyperdrive-id>"
localConnectionString = "postgres://localhost/seams_adapter"
```

When the Postgres adapter is enabled in a Worker, the Wrangler compatibility
date must be September 23, 2024 or later and Node.js compatibility must be
enabled for the database driver:

```toml
compatibility_date = "2026-06-26"
compatibility_flags = ["nodejs_compat"]
```

Validate the final `wrangler.toml` against the repository-pinned Wrangler
version before implementing the first migration:

```bash
pnpm wrangler types
pnpm wrangler deploy --dry-run
```

`preview_database_id` is a local or preview D1 identifier. It must be present
for local test flows that call Wrangler's programmatic dev API and for
`wrangler dev --remote`; default local `wrangler dev` persists to local storage
without touching the remote `database_id`.

Local commands:

```bash
pnpm wrangler d1 migrations apply seams-console --local
pnpm wrangler d1 migrations apply seams-signer --local
pnpm wrangler d1 execute seams-console --local --command "SELECT 1"
pnpm wrangler d1 execute seams-signer --local --command "SELECT 1"
pnpm wrangler dev --persist-to .wrangler/state/seams-d1
```

Postgres adapter local commands:

```bash
POSTGRES_ADAPTER_TEST_URL=postgres://localhost/seams_adapter pnpm postgres:adapter:migrate
POSTGRES_ADAPTER_TEST_URL=postgres://localhost/seams_adapter pnpm postgres:adapter:test
POSTGRES_ADAPTER_TEST_URL=postgres://localhost/seams_adapter pnpm worker:dev:postgres-adapter
```

The default local path remains D1 plus local Durable Objects. Postgres adapter
tests run explicitly because they exercise the larger-limit escape hatch rather
than the default product path.

Remote commands:

```bash
pnpm wrangler d1 migrations apply seams-console --remote
pnpm wrangler d1 migrations apply seams-signer --remote
pnpm wrangler d1 execute seams-console --remote --command "SELECT 1"
pnpm wrangler d1 execute seams-signer --remote --command "SELECT 1"
```

Local inspection:

- Open the SQLite files under `.wrangler/state/seams-d1` in TablePlus using the
  SQLite driver.
- Treat TablePlus as read-only inspection. Schema and data changes must go
  through D1 migrations, seed scripts, or Worker test harnesses.
- Remote D1 has no TablePlus TCP endpoint. Use `wrangler d1 execute`,
  `wrangler d1 export`, the Cloudflare dashboard, or a purpose-built admin route
  for remote inspection.

Testing target:

- Use `@cloudflare/vitest-pool-workers` for Worker integration tests.
- Use Miniflare only where direct binding access is simpler.
- Apply D1 migrations in test setup.
- Keep small fakes only for pure unit tests that do not exercise SQL behavior.

Local D1 constraints to remember:

- `wrangler dev` uses local mode by default and persists local state across runs.
- Local D1 data is separate from remote D1 data.
- Local Durable Object state is also local Wrangler/Miniflare state.
- Tests that require a clean database should drop/recreate tables or use isolated
  Workers Vitest storage.
- Read-replication metadata is a production concern and should not drive local
  test assertions.

## D1 Design Constraints

D1 uses SQLite semantics and Cloudflare Worker bindings.

Design around these platform constraints:

- paid-plan D1 databases are capped at 10 GB per database
- individual databases process queries one at a time
- individual queries have a 30 second duration limit
- each statement can bind at most 100 parameters
- each table can have at most 100 columns
- each row/blob/string value can be at most 2 MB
- D1 batches execute statements sequentially and roll back the sequence on
  failure
- D1 supports SQLite triggers. Use triggers only when the trigger behavior is
  covered by local and remote D1 integration tests.

Operational consequences:

- Shard large tenants or high-volume domains by tenant/entity D1 database.
- Keep dashboard queries index-first and page-first.
- Store observability rollups separately from raw events when volume grows.
- Use append-only event tables for billing evidence.
- Keep mutations small and retryable.
- Multi-row invariants that need rollback must use one `D1Database.batch()` or a
  trigger-enforced SQLite statement. D1 `batch()` is a SQL transaction: if one
  statement fails, the whole sequence rolls back.
- Billing reservations must use atomic D1/SQLite. A reserve operation cannot
  split an idempotent debit into an unguarded `UPDATE` followed by a later
  `INSERT`.

## Tenant Isolation

D1 has no Postgres RLS equivalent.

Use explicit tenant scoping in every schema and every query:

```sql
CREATE TABLE console_projects (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id)
);
```

Access rules:

- Route auth resolves `ConsoleTenantContext` once.
- Storage methods require `ConsoleTenantContext`.
- Storage methods bind `namespace` and `org_id` in every query.
- Domain services never accept raw tenant strings from request bodies.
- Tenant context is a required object, not optional method parameters.

Optional hard isolation:

- Use one D1 database per enterprise tenant if D1 limits and operational tooling
  permit it.
- Keep small shared-tenancy D1 databases for development and low-risk tenants.
- Store database binding resolution at the request boundary.

Signer access uses a separate required context because custody and wallet
identity are different from console dashboard tenancy:

```ts
type SignerTenantContext =
  | {
      kind: 'wallet_signer_context';
      namespace: NamespaceId;
      orgId: OrgId;
      projectId: ProjectId;
      envId: EnvironmentId;
      walletId: WalletId;
      rpId: RelyingPartyId;
      actor: SignerActor;
    }
  | {
      kind: 'signing_root_custody_context';
      namespace: NamespaceId;
      orgId: OrgId;
      projectId: ProjectId;
      envId: EnvironmentId;
      signingRootId: SigningRootId;
      signingRootVersion: SigningRootVersion;
      custodyWorker: 'hosted_signer';
    };
```

Signer rules:

- Route auth or Worker service authentication resolves `SignerTenantContext`
  once.
- Signer metadata methods require the wallet branch.
- Sealed share reads and decrypt operations require the custody branch.
- Console routes can call signer read models through service methods, and cannot
  import or receive signer KEK bindings.
- Raw wallet, relying-party, signing-root, org, project, and environment strings
  are parsed at the request or persistence boundary.

## Multi-Tenancy Architecture Decisions

Use shared D1 databases for the first release, with a storage routing boundary
from day one. D1 is designed for horizontal scale across smaller databases, and
the 10 GB per-database limit is a hard cap. The codebase should be ready to move
one tenant to a different D1 database without changing core wallet, billing, or
signer logic.

### First-Release Topology

Recommended default:

- One shared `CONSOLE_DB` for console metadata.
- One shared `SIGNER_DB` for signer metadata and sealed signer ciphertext.
- One shared `THRESHOLD_STORE` namespace for signer coordination.
- One hosted Cloudflare Secrets Store binding for signer KEKs, with KEK records
  scoped to one org or one enterprise tenant. Shared development tenants may use
  one namespace-level test KEK only outside production.
- Redacted raw observability stays in D1 only inside the observability operating
  envelope.

This is the smallest production topology. It keeps local development simple and
still lets the architecture grow by changing tenant storage routes.

### Tenant Storage Route

Add a required routing boundary before any storage call that needs a D1 binding,
Durable Object namespace, or KEK provider:

```ts
type D1DoRouteTargets = {
  console: Extract<ConsoleStorageTarget, { kind: 'd1' }>;
  signer: Extract<SignerStorageTarget, { kind: 'cloudflare_d1_do' }>;
};

type PostgresRouteTargets = {
  console: Extract<ConsoleStorageTarget, { kind: 'postgres' }>;
  signer: Extract<SignerStorageTarget, { kind: 'postgres' }>;
};

type TenantStorageRoute =
  | ({
      kind: 'shared';
      namespace: NamespaceId;
      orgId: OrgId;
      routeVersion: RouteVersion;
      shardId?: never;
    } & D1DoRouteTargets)
  | ({
      kind: 'dedicated_tenant';
      namespace: NamespaceId;
      orgId: OrgId;
      routeVersion: RouteVersion;
      jurisdiction: TenantDataJurisdiction;
      shardId?: never;
    } & D1DoRouteTargets)
  | ({
      kind: 'tenant_shard';
      namespace: NamespaceId;
      orgId: OrgId;
      routeVersion: RouteVersion;
      jurisdiction: TenantDataJurisdiction;
      shardId: TenantShardId;
    } & D1DoRouteTargets)
  | ({
      kind: 'postgres_large_tenant';
      namespace: NamespaceId;
      orgId: OrgId;
      routeVersion: RouteVersion;
      migrationReason: 'd1_size_limit' | 'd1_throughput_limit' | 'logical_database_required';
      shardId?: never;
    } & PostgresRouteTargets);
```

Rules:

- Request auth resolves `TenantStorageRoute` after resolving tenant identity.
- Domain logic receives stores. Raw D1 bindings and binding names stay at the
  request/storage boundary.
- Route resolution happens once per request and is included in storage
  diagnostics.
- Route changes are versioned. A stale request that writes with an old
  `routeVersion` fails with `tenant_route_changed`.
- The first implementation returns the `shared` branch for every tenant.
- Before introducing the first tenant-specific D1 or Postgres route, add
  `TENANT_ROUTE_DB` as a small dedicated D1 route registry. It is a deployment
  registry, not tenant data, and is always bound directly to the Worker.
- Before introducing the first Postgres route, add Hyperdrive bindings and
  Postgres schema migrations for the adapter.
- Worker D1 bindings are finite. If tenant-specific databases exceed what one
  Worker script can bind cleanly, split by Worker/service route group rather than
  loading every D1 binding into one Worker.

### Tenant Route Registry

The route registry becomes mandatory before any route differs from the shared
default. The registry itself is not resolved through `TenantStorageRoute`; it is
read from a dedicated `TENANT_ROUTE_DB` binding during request setup.

Registry table:

```sql
CREATE TABLE tenant_storage_routes (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  route_version INTEGER NOT NULL,
  route_kind TEXT NOT NULL,
  route_state TEXT NOT NULL,
  console_target_json TEXT NOT NULL,
  signer_target_json TEXT NOT NULL,
  jurisdiction TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  migration_id TEXT,
  freeze_reason TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id),
  CHECK (route_kind IN (
    'shared',
    'dedicated_tenant',
    'tenant_shard',
    'postgres_large_tenant'
  )),
  CHECK (route_state IN ('active', 'write_frozen', 'moving', 'archived'))
);
```

Migration table:

```sql
CREATE TABLE tenant_route_migrations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  migration_id TEXT NOT NULL,
  from_route_version INTEGER NOT NULL,
  target_route_kind TEXT NOT NULL,
  target_console_json TEXT NOT NULL,
  target_signer_json TEXT NOT NULL,
  target_jurisdiction TEXT NOT NULL,
  target_schema_version INTEGER NOT NULL,
  migration_state TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  completed_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, migration_id),
  CHECK (migration_state IN (
    'planned',
    'write_frozen',
    'importing',
    'verified',
    'activated',
    'aborted'
  ))
);
```

Resolution rules:

- Missing registry rows resolve to the compiled shared D1/DO route.
- Registry rows are parsed into `TenantStorageRoute` at the request boundary.
- Route target JSON is validated into branch-specific target types. Invalid
  target combinations fail closed before any domain store is created.
- `schema_version` must be less than or equal to the running adapter schema
  version. Requests fail with `tenant_route_schema_too_new` when the route needs
  a newer adapter.
- Active request handlers keep the route only for that request. Process-level
  route caches are allowed only with a short TTL and must be bypassed for admin,
  migration, billing, and signer writes.

Route switch protocol:

1. Insert a `tenant_route_migrations` row with the pending target JSON and
   `from_route_version`.
2. Set the current route row to `write_frozen` with
   `WHERE route_version = :currentVersion`.
3. Stop new writes and wait for in-flight writes using the old version to finish
   or fail with `tenant_route_changed`.
4. Run export, import, and parity checks against the pending target from the
   migration row.
5. Mark the migration row `verified`.
6. Update route target JSON, `route_kind`, `jurisdiction`, `schema_version`, and
   `route_state = 'active'` with
   `WHERE route_version = :frozenVersion AND route_state = 'write_frozen'`.
7. Increment `route_version` in the same update.
8. Mark the migration row `activated`.
9. Reopen writes after the resolver returns the new active route.

Failed compare-and-set updates mean another migration changed the route. Abort
the move and rerun from route discovery.

### Scaling Order

When a shared signer or console D1 approaches its operating envelope, use this
order:

1. Move cold and high-volume data out of D1. Observability raw events, old
   sponsored execution details, bulky audit payloads, and long-retention
   snapshots should move to R2, Analytics Engine, Cloudflare Logs, or another
   archive store before wallet metadata is sharded.
2. Move one large enterprise tenant to dedicated `CONSOLE_DB` and `SIGNER_DB`
   bindings. This is the preferred escape hatch when one tenant is materially
   larger than the rest.
3. Add tenant-hash D1 shards when many tenants grow gradually and no single
   tenant justifies a dedicated database.
4. Add wallet/entity shards only if one tenant has enough wallets that a single
   tenant database cannot hold them. This is the highest D1 complexity option
   because org-level queries span multiple databases.
5. Route the tenant, shard, or deployment to the Postgres backend adapter if the
   product needs one logical relational database above 10 GB with broad
   cross-tenant or cross-wallet queries. This is a full-family route move for
   all route-owned persistence.

Do not shard by wallet in the first release.

### Postgres Backend Adapter

Postgres is the escape hatch for larger limits and relational features. It is a
backend adapter, selected by `TenantStorageRoute`, using the same domain-store
ports as D1.

Postgres migration scope is full-family only. When a tenant, shard, or
deployment moves to Postgres, all route-owned persistence moves together:
console metadata, signer metadata, sealed signer ciphertext, signer
coordination, billing, sponsored execution records, runtime snapshots, snapshot
outbox, and route-owned reconciliation data. There is no supported state where
console uses D1 while signer uses Postgres, signer uses D1 while billing uses
Postgres, or any other partial backend split.

Recommendations:

- Keep D1/DO as the default first-release backend.
- Implement Postgres adapters for the same console and signer store contracts.
- Use Cloudflare Hyperdrive for Worker runtime Postgres access.
- Use direct Postgres pools only in local tooling and migration scripts.
- Keep Postgres schema migrations beside D1 migrations, scoped to adapter-owned
  schemas.
- Run contract tests against both D1 and Postgres for billing reservations,
  sponsored execution settlement, snapshot outbox claiming, tenant scoping,
  signer metadata, sealed share records, and signer coordination.

Postgres adapter concurrency:

- Billing reservations use transactions and row locks.
- Snapshot outbox claiming can use `FOR UPDATE SKIP LOCKED`.
- Signer budgets and presignature pools can use row locks and unique
  idempotency indexes.
- Tenant isolation remains explicit in queries and contexts. Postgres RLS may be
  added inside the adapter as defense in depth, while core logic still requires
  tenant contexts.

Postgres route triggers:

- A shared or dedicated D1 database reaches the 8 GB move/offload threshold and
  wallet/signature metadata is the dominant storage source.
- A tenant requires one logical database above 10 GB.
- A tenant requires database-level backup/restore or operational tooling that is
  materially stronger in Postgres.
- Query patterns need relational features that would make D1 sharding too
  complex.

Postgres migration path:

1. Provision Postgres and Hyperdrive.
2. Apply Postgres adapter migrations.
3. Freeze the tenant's writes through the route registry.
4. Export all tenant-scoped D1/DO route state: console metadata, signer
   metadata, sealed signer ciphertext, signer coordination, billing, sponsored
   execution records, runtime snapshots, snapshot outbox, and route-owned
   reconciliation data.
5. Parse exports into internal domain types.
6. Import through Postgres adapters.
7. Run backend contract tests and tenant smoke tests against the Postgres route.
8. Switch `TenantStorageRoute` to `postgres_large_tenant` through the registry
   compare-and-set protocol.
9. Reopen writes.
10. Keep source D1 rows read-only through the archive window, then delete in
    small batches.

### Dedicated Tenant Criteria

Move a tenant to a dedicated D1 route when any condition is true:

- The tenant requires contractual database-level isolation.
- The tenant needs database-level restore, export, or deletion semantics.
- The tenant's signer or console rows exceed 2 GB.
- The tenant consumes more than 30 percent of shared D1 storage.
- The shared database reaches 7 GB and one tenant is the largest contributor.
- The tenant repeatedly causes D1 overload, queueing, or query latency incidents.
- The tenant needs a customer-managed KMS/HSM or dedicated KEK lifecycle.

Shared database operating thresholds:

- Alert at 7 GB.
- Prepare a tenant move or cold-data offload at 8 GB.
- Freeze new high-volume writes and execute the move/offload plan before 9 GB.
- Never plan to operate close to the 10 GB D1 hard cap.

### Tenant Move Procedure

Moving a tenant to another D1 database is a controlled migration:

1. Create the new D1 database and apply the same migrations.
2. Bind the database in the target Worker or route group.
3. Add or update the route registry entry to `write_frozen` with the current
   `routeVersion`.
4. Freeze tenant writes for console, signer metadata, sponsored EVM settlement,
   billing reservations, and snapshot outbox.
5. Export tenant-scoped rows from the source D1 as normalized JSONL.
6. Parse exported rows into internal domain types.
7. Import into the target D1 in bounded `D1Database.batch()` chunks.
8. Drain or expire active Durable Object coordination state when the
   `thresholdStore` binding changes. If the DO binding stays the same, keep the
   object names unchanged.
9. Run record-count, key-identity, billing-balance, sealed-share, and signing
   smoke checks against the target route.
10. Atomically switch the route entry to active with the registry compare-and-set
    protocol and a new `routeVersion`.
11. Reopen writes.
12. Keep source rows read-only until the archive window ends, then delete in
    small batches.

### Data Location And Jurisdiction

Use automatic D1 placement for shared first-release databases. Create dedicated
D1 databases with an explicit jurisdiction only when a contract or compliance
requirement needs it. D1 jurisdiction is chosen at database creation and cannot
be added or changed later, so the route registry records the chosen
`jurisdiction` for every dedicated route.

Rules:

- `shared` routes use `jurisdiction = 'automatic'`.
- `dedicated_tenant` and `tenant_shard` routes must record the D1 jurisdiction
  or `automatic`.
- `postgres_large_tenant` routes must record the Postgres region, backup region,
  and Hyperdrive configuration ID in the target JSON.
- A tenant move that changes jurisdiction is a full route migration with write
  freeze, export/import, parity checks, and a new `routeVersion`.
- Dedicated route creation must be part of sales/security review when data
  residency is contractual.

### Tenant Restore And Delete

Shared D1 Time Travel restores affect the whole database. Tenant-level restore in
shared D1 must use tenant-scoped export/replay tooling. Enterprise tenants that
need database-level restore should use dedicated D1 databases.

### Backup And Recovery Policy

Use D1 Time Travel as the primary short-term recovery layer and R2 exports as
the long-retention archive layer.

Policy:

- D1 production databases must use the production storage backend that supports
  Time Travel. Verify with `wrangler d1 info DB_NAME` before production cutover.
- Time Travel is the primary recovery tool for operational mistakes: failed
  migrations, accidental deletes, bad updates, and deploy regressions.
- Capture `wrangler d1 time-travel info DB_NAME` bookmarks before every schema
  migration, data import, tenant move, route switch, and destructive maintenance
  job.
- Keep weekly exports of `CONSOLE_DB`, `SIGNER_DB`, and `TENANT_ROUTE_DB` in R2.
- Keep weekly exports for every dedicated tenant D1 and tenant-shard D1.
- Retain weekly R2 exports for at least 12 weeks unless a stricter customer or
  compliance policy applies.
- R2 export object names include database name, route kind, route version,
  schema version, export timestamp, and source Time Travel bookmark.
- R2 export metadata records row counts, table checksums where practical,
  signer sealed-share counts, billing summary totals, and export tool version.
- R2 exports are encrypted at rest by Cloudflare. Signer shares remain
  application-encrypted ciphertext; KEKs are never exported to D1 or R2.
- Restore drills run in staging at least monthly: restore from Time Travel, load
  the latest R2 export into a new D1 database, and run the tenant smoke suite.
- Production restore runbooks must always capture the current bookmark before an
  in-place Time Travel restore so the restore can be undone.

Restore guidance:

- Use Time Travel for restores inside the D1 retention window.
- Use R2 exports for restores outside the Time Travel window or for independent
  audit/archive recovery.
- For shared D1 databases, prefer tenant-scoped export/replay over whole-DB
  restore unless the incident affects the entire database.
- For dedicated tenant D1 databases, whole-database Time Travel restore is
  acceptable after freezing writes and notifying affected operators.

Tenant deletion rules:

- First mark the tenant as `deletion_pending`.
- Stop new writes and signing sessions.
- Revoke API keys, publishable keys, and active sessions.
- Destroy or retire the tenant KEK where custody policy allows cryptographic
  erasure.
- Delete D1 rows in small batches.
- Keep redacted audit tombstones only for the required retention window.
- Record every deletion step as a tenant-scoped audit event.
- Shared D1 Time Travel, D1 backups, Postgres backups, and exported migration
  archives may retain encrypted tenant data until their retention windows end.
  Tenant deletion reports must state this retention window.
- For encrypted signer data, cryptographic erasure is completed by retiring or
  destroying the tenant KEK according to custody policy.

### Durable Object Tenancy

Keep one `THRESHOLD_STORE` namespace for the first release. The object names
already include `namespace` and the coordination atom, which gives the needed
per-entity serialization.

Rules:

- DO names must include `namespace`.
- DO names must include exactly one coordination atom: wallet, signing root,
  relayer key, or session.
- Do not introduce a global tenant coordination object.
- Dedicated DO namespaces are introduced only after measured hot-tenant
  contention or operational isolation requires them.
- If a tenant moves to a new DO namespace, use the signer cutover drain policy:
  disable new active coordination, wait for TTLs, import only durable status, and
  start fresh active coordination in the target namespace.

### Billing Tenancy

Billing remains org-scoped:

- Prepaid summary primary key is `(namespace, org_id)`.
- Reservation, ledger, sponsored execution, and reconciliation uniqueness is
  scoped by `(namespace, org_id)`.
- No billing reservation, settlement, credit transfer, or ledger correction can
  cross org boundaries.
- Tenant moves must verify prepaid summary totals equal reservation events plus
  ledger entries before route activation.

### Operational Access

Support and migration tooling must be tenant-scoped:

- Support routes require a resolved `TenantStorageRoute`.
- Support routes can inspect metadata and ciphertext only. They cannot decrypt
  signer shares or access KEKs.
- Data export, route changes, tenant moves, restore, delete, and support reads
  write tenant-scoped audit events.
- Migration admin routes are removed after cutover or tenant move completion.

## Signer Persistence

Treat `seams_signer` as a persistence domain made of metadata, sealed
ciphertext, and hot coordination state.

D1/DO is the first active signer backend. Postgres remains a signer backend
adapter behind the same `SignerMetadataStore` and `SignerCoordinationStore`
ports for tenants or deployments routed to `postgres_large_tenant`.

### D1-Owned Signer Data

D1 owns signer records that need relational lookup, dashboard/admin visibility,
or import/export checks:

- `webauthn_authenticators`
- `webauthn_credential_bindings`
- `webauthn_challenges`
- `wallet_registration_intents`
- `wallet_registration_ceremonies`
- `wallets`
- `wallet_auth_methods`
- `wallet_signers`
- `email_otp_challenges`
- `email_otp_grants`
- `email_otp_wallet_enrollments`
- `email_otp_recovery_wrapped_enrollment_escrows`
- `email_otp_auth_states`
- `email_otp_unlock_challenges`
- `email_otp_registration_attempts`
- `threshold_ed25519_keys`
- `threshold_ecdsa_keys`
- `signing_root_secret_shares`
- `device_linking_sessions`
- `email_recovery_preparations`
- `near_public_keys`
- `identity_links`
- `app_session_versions`
- `recovery_sessions`
- `recovery_executions`

D1 signer tables use `TEXT` JSON columns, extracted indexed columns for lookup,
and required tenant fields. ECDSA key identity uses a base table plus explicit
identity tables. This replaces Postgres partial unique indexes with D1-enforced
primary keys:

```sql
CREATE TABLE signer_threshold_ecdsa_keys (
  namespace TEXT NOT NULL,
  relayer_key_id TEXT NOT NULL,
  owner_address TEXT,
  public_key_b64u TEXT,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, relayer_key_id)
);

CREATE TABLE signer_threshold_ecdsa_key_handle_identities (
  namespace TEXT NOT NULL,
  key_handle TEXT NOT NULL,
  relayer_key_id TEXT NOT NULL,
  PRIMARY KEY (namespace, key_handle),
  UNIQUE (namespace, relayer_key_id),
  FOREIGN KEY (namespace, relayer_key_id)
    REFERENCES signer_threshold_ecdsa_keys (namespace, relayer_key_id)
    ON DELETE CASCADE
);

CREATE TABLE signer_threshold_ecdsa_threshold_identities (
  namespace TEXT NOT NULL,
  threshold_key_id TEXT NOT NULL,
  signing_root_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  relayer_key_id TEXT NOT NULL,
  PRIMARY KEY (
    namespace,
    threshold_key_id,
    signing_root_id,
    signing_root_version
  ),
  UNIQUE (namespace, relayer_key_id),
  FOREIGN KEY (namespace, relayer_key_id)
    REFERENCES signer_threshold_ecdsa_keys (namespace, relayer_key_id)
    ON DELETE CASCADE
);

CREATE TABLE signer_threshold_ecdsa_wallet_identities (
  namespace TEXT NOT NULL,
  wallet_id TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  signing_root_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  relayer_key_id TEXT NOT NULL,
  PRIMARY KEY (
    namespace,
    wallet_id,
    rp_id,
    signing_root_id,
    signing_root_version
  ),
  UNIQUE (namespace, relayer_key_id),
  FOREIGN KEY (namespace, relayer_key_id)
    REFERENCES signer_threshold_ecdsa_keys (namespace, relayer_key_id)
    ON DELETE CASCADE
);

CREATE TRIGGER signer_ecdsa_threshold_identity_exclusive
BEFORE INSERT ON signer_threshold_ecdsa_threshold_identities
WHEN EXISTS (
  SELECT 1
    FROM signer_threshold_ecdsa_wallet_identities
   WHERE namespace = NEW.namespace
     AND relayer_key_id = NEW.relayer_key_id
)
BEGIN
  SELECT RAISE(ABORT, 'ecdsa_identity_conflict');
END;

CREATE TRIGGER signer_ecdsa_wallet_identity_exclusive
BEFORE INSERT ON signer_threshold_ecdsa_wallet_identities
WHEN EXISTS (
  SELECT 1
    FROM signer_threshold_ecdsa_threshold_identities
   WHERE namespace = NEW.namespace
     AND relayer_key_id = NEW.relayer_key_id
)
BEGIN
  SELECT RAISE(ABORT, 'ecdsa_identity_conflict');
END;
```

D1 writer rules:

- Insert the base key row and identity rows in one `D1Database.batch()`.
- A key with `key_handle` inserts one key-handle identity row.
- A key with threshold identity inserts one threshold identity row.
- A key with wallet identity inserts one wallet identity row.
- A key cannot have both threshold identity and wallet identity.
- A key must have at least one identity row.
- D1 row parsers join the identity tables and reject base rows with no identity.

Internal key identity uses a discriminated union:

```ts
type SignerEcdsaKeyHandle =
  | { kind: 'with_key_handle'; keyHandle: KeyHandle }
  | { kind: 'without_key_handle'; keyHandle?: never };

type SignerEcdsaKeyIdentity =
  | {
      kind: 'threshold_identity';
      thresholdKeyId: ThresholdKeyId;
      signingRootId: SigningRootId;
      signingRootVersion: SigningRootVersion;
      handle: SignerEcdsaKeyHandle;
      walletId?: never;
      rpId?: never;
    }
  | {
      kind: 'wallet_identity';
      walletId: WalletId;
      rpId: RelyingPartyId;
      signingRootId: SigningRootId;
      signingRootVersion: SigningRootVersion;
      handle: SignerEcdsaKeyHandle;
      thresholdKeyId?: never;
    }
  | {
      kind: 'key_handle_identity';
      handle: { kind: 'with_key_handle'; keyHandle: KeyHandle };
      thresholdKeyId?: never;
      walletId?: never;
      rpId?: never;
      signingRootId?: never;
      signingRootVersion?: never;
    };
```

### Encrypted Signer Secrets

D1 may store sealed ciphertext records. D1 must never store plaintext signing
shares, root shares, private keys, KEKs, or API secrets.

```sql
CREATE TABLE signer_signing_root_secret_shares (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  env_id TEXT NOT NULL,
  signing_root_id TEXT NOT NULL,
  signing_root_version TEXT NOT NULL,
  share_id INTEGER NOT NULL,
  sealed_share_b64u TEXT NOT NULL,
  storage_id TEXT,
  kek_id TEXT NOT NULL,
  envelope_version TEXT NOT NULL,
  aad_digest_b64u TEXT NOT NULL,
  ciphertext_digest_b64u TEXT NOT NULL,
  rotation_state TEXT NOT NULL,
  rotated_from_kek_id TEXT,
  rotated_at_ms INTEGER,
  retired_at_ms INTEGER,
  last_audit_event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (
    namespace,
    org_id,
    signing_root_id,
    signing_root_version,
    share_id
  ),
  CHECK (share_id IN (1, 2, 3)),
  CHECK (rotation_state IN ('active', 'rotation_pending', 'rotated', 'retired'))
);
```

Rules:

- Hosted production KEKs live in Cloudflare Secrets Store and are scoped to one
  org or one enterprise tenant.
- Local development and self-host examples may use Wrangler secrets.
- Enterprise custody may use an external KMS/HSM through a signer-only service
  binding.
- The console Worker cannot receive signer KEKs.
- The signer Worker decrypts only the share material needed for the requested
  operation.
- The encryption AAD includes `namespace`, `org_id`, `project_id`, `env_id`,
  `signing_root_id`, `signing_root_version`, and `share_id`.
- Every sealed record carries `kek_id`, `envelope_version`, AAD digest,
  ciphertext digest, rotation state, and last audit event ID.
- D1 export files, local D1 files, and backups are sensitive because they contain
  durable ciphertext.
- Existing Postgres rows with missing `kek_id` fail migration unless an explicit
  migration manifest maps them to a verified KEK or re-envelopes them before
  import.
- Import tools may handle plaintext only inside a one-time migration process
  memory boundary. Plaintext shares cannot be logged, written to disk, returned
  in HTTP responses, or stored in D1 or DO storage.

Signer KEK provider state:

```ts
type SigningRootEncodedKekMaterialEncoding = 'base64url' | 'base64' | 'hex';

type CloudflareSecretsStoreSecretBinding = {
  get(): Promise<string | null>;
};

type SigningRootExternalKmsKekResolutionResult =
  | { kind: 'raw_key_bytes'; keyBytes: Uint8Array; key?: never; encodedKey?: never; encoding?: never }
  | { kind: 'crypto_key'; key: CryptoKey; keyBytes?: never; encodedKey?: never; encoding?: never }
  | {
      kind: 'encoded_key';
      encodedKey: string;
      encoding: SigningRootEncodedKekMaterialEncoding;
      keyBytes?: never;
      key?: never;
    };

type SigningRootExternalKmsKekClient = {
  resolveSigningRootAesGcmKek(
    input: SigningRootSecretShareKekResolutionInput,
  ): Promise<SigningRootExternalKmsKekResolutionResult>;
};

type SignerKekProvider =
  | {
      kind: 'cloudflare_secrets_store';
      secretsByKekId: Readonly<Record<KekId, CloudflareSecretsStoreSecretBinding>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      workerSecretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'worker_secret';
      workerSecretsByKekId: Readonly<Record<KekId, string>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      secretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'external_kms';
      externalKmsClient: SigningRootExternalKmsKekClient;
      secretsByKekId?: never;
      workerSecretsByKekId?: never;
      encoding?: never;
    };

type SealedSignerShareState =
  | {
      state: 'active';
      kekId: KekId;
      envelopeVersion: EnvelopeVersion;
      aadDigestB64u: Base64UrlText;
      ciphertextDigestB64u: Base64UrlText;
    }
  | {
      state: 'rotation_pending';
      currentKekId: KekId;
      nextKekId: KekId;
      envelopeVersion: EnvelopeVersion;
      aadDigestB64u: Base64UrlText;
      ciphertextDigestB64u: Base64UrlText;
    }
  | {
      state: 'rotated';
      kekId: KekId;
      rotatedFromKekId: KekId;
      rotatedAtMs: UnixMs;
      envelopeVersion: EnvelopeVersion;
      aadDigestB64u: Base64UrlText;
      ciphertextDigestB64u: Base64UrlText;
    }
  | {
      state: 'retired';
      kekId: KekId;
      retiredAtMs: UnixMs;
      envelopeVersion: EnvelopeVersion;
      aadDigestB64u: Base64UrlText;
      ciphertextDigestB64u: Base64UrlText;
    };
```

Signer KEK adapter rules:

- Core sealing code depends only on `SigningRootSecretShareKekResolver`.
- `SignerKekProvider` is parsed at the Worker boundary and converted into that
  resolver.
- Cloudflare Secrets Store is the hosted default. Each KEK version is a distinct
  Secrets Store secret bound to the signer Worker, and `secretsByKekId` maps the
  persisted `kek_id` to that binding.
- Worker secrets are allowed for local development and self-host deployments.
- External KMS/HSM support goes through a signer-only service binding or client
  that returns raw key bytes, a non-extractable `CryptoKey`, or encoded key
  material. The console Worker never receives this client.
- Encoded key material must be `base64url`, `base64`, or `hex` and must decode to
  a valid AES-256-GCM KEK before use.
- Invalid provider branch combinations fail at compile time through
  `@ts-expect-error` fixtures.

### Durable Object-Owned Signer State

Durable Objects own per-entity state that needs serialized updates:

- signing-session use-count consumption
- idempotency consumption guards
- wallet signing budget reservation, commit, release, and validation
- ECDSA presignature put/reserve/take/discard
- ECDSA pool-fill session compare-and-swap advancement
- Ed25519 presign capacity and rate limiting
- signing-root status and short-lived signer coordination
- replay guards and temporary activation records

Use SQLite-backed Durable Objects for new namespaces. Route each operation to a
deterministic object name that represents the coordination atom:

```text
threshold-store:namespace:{namespace}:wallet:{walletId}
threshold-store:namespace:{namespace}:signing-root:{signingRootId}:{signingRootVersion}
threshold-store:namespace:{namespace}:relayer-key:{relayerKeyId}
threshold-store:namespace:{namespace}:session:{sessionId}
```

Operation ownership:

| Operation | Object name | DO SQL tables |
| --- | --- | --- |
| signing-session use count and idempotency | `threshold-store:namespace:{namespace}:session:{sessionId}` | `session_state`, `session_consumptions` |
| wallet budget reserve/commit/release/validate | `threshold-store:namespace:{namespace}:session:{sessionId}` | `session_state`, `budget_reservations`, `budget_commits` |
| ECDSA presignature put/reserve/take/discard | `threshold-store:namespace:{namespace}:relayer-key:{relayerKeyId}` | `ecdsa_presignatures`, `ecdsa_presignature_reservations` |
| ECDSA pool-fill CAS advancement | `threshold-store:namespace:{namespace}:relayer-key:{relayerKeyId}` | `ecdsa_pool_fill_sessions` |
| Ed25519 presign capacity and rate limit | `threshold-store:namespace:{namespace}:wallet:{walletId}` | `ed25519_presignatures`, `ed25519_presign_indexes`, `rate_limits` |
| signing-root status and replay guards | `threshold-store:namespace:{namespace}:signing-root:{signingRootId}:{signingRootVersion}` | `signing_root_status`, `replay_guards` |

Rules:

- Use `getByName()` with deterministic names.
- Use one DO per coordination atom.
- Persist before updating any in-memory cache.
- Keep `blockConcurrencyWhile()` limited to constructor schema setup.
- Avoid external network I/O inside a critical storage mutation.
- Use alarms for expiry cleanup where per-object cleanup is useful.
- Keep large queryable inventory in D1, with the DO storing only hot serialized
  state and compact indexes.
- Avoid cross-object transactions. When a workflow touches two coordination
  atoms, create an idempotent intent in the first object and commit it in the
  second object with the same operation key.
- All DO mutation methods return typed result unions. They do not return raw
  storage rows.

`ThresholdStoreDurableObject` v2 work:

- Keep the binding name `THRESHOLD_STORE`.
- Convert the class to `extends DurableObject<Env>`.
- Use `ctx.storage.sql.exec()` and a `_sql_schema_migrations` table for DO
  schema versions. `PRAGMA user_version` is not used.
- Move schema setup into the constructor under `ctx.blockConcurrencyWhile()`.
- Replace the fetch JSON operation surface with typed RPC methods for new
  callers.
- If an import-only fetch route is needed, keep it behind the migration admin
  boundary and delete it before production cutover.
- Port the existing unit tests that instantiate `ThresholdStoreDurableObject`
  directly to Workers Vitest or a local DO SQL test harness.

### Postgres Signer Adapter Parity

The Postgres signer adapter implements the same logical model as D1/DO without
reintroducing direct legacy Postgres service paths.

Required Postgres signer behavior:

- Signer metadata tables contain the same required tenant, identity, lifecycle,
  ciphertext, digest, AAD, KEK, and audit fields as the D1 schema.
- ECDSA identity exclusivity is enforced with unique indexes and adapter-owned
  constraints or triggers. A base key without exactly one supported identity
  branch is rejected at the read boundary.
- Sealed share rows are ciphertext-only. Plaintext shares, root shares, private
  keys, KEKs, and API secrets cannot be stored in Postgres.
- `SignerMetadataStore` methods parse Postgres rows into the same internal
  discriminated unions as the D1 adapter.
- `SignerCoordinationStore` methods use transactions, row locks, and unique
  idempotency indexes to match the Durable Object RPC result unions for budget
  reserve/commit/release, replay guards, signing-session consumption,
  presignature reserve/take/discard, and pool-fill CAS.
- Postgres signer coordination state is tenant-scoped by `(namespace, org_id)`
  and by the same coordination atom used in DO names: wallet, signing root,
  relayer key, or session.
- Runtime routes cannot mix D1 signer metadata with Postgres signer
  coordination. A tenant route is either D1/DO or Postgres.

### Signer Read Models

Some signer data spans D1 and Durable Objects. Build read models deliberately:

- D1 provides admin/search views for wallets, auth methods, threshold keys,
  signing roots, and recovery records.
- Durable Objects expose narrow status methods for active session budget,
  presignature pool depth, and signing-root coordination status.
- Dashboard routes should read D1 first, then call DO status methods only for
  specific entities shown on the page.

### Signer Migration Cut Line

Cut signer storage over domain by domain:

1. Move queryable signer metadata to D1.
2. Move sealed signing-root share ciphertext to D1 with external KEKs.
3. Move hot coordination state to Durable Objects.
4. Run parity tests against Postgres fixture exports.
5. Freeze Postgres signer writes.
6. Apply final D1 import and DO activation bundle import.
7. Start Worker runtime using `SIGNER_DB` and `THRESHOLD_STORE`.
8. Archive signer Postgres.

Cutover quiescence policy:

1. Disable creation of new signer sessions, budget reservations, replay guards,
   and presignature reservations.
2. Keep read-only signer metadata routes available for dashboard support.
3. Wait until active session TTL, budget reservation TTL, replay guard TTL, and
   presignature reservation TTL have elapsed.
4. Import only active long-lived metadata, sealed ciphertext, available
   presignature inventory, and signing-root status.
5. Drop expired sessions, consumed idempotency keys, expired replay guards,
   in-flight budget reservations, and reserved presignatures during import.
6. Run signing, budget, and presignature parity tests against the imported D1/DO
   state.
7. Enable the Worker runtime using `SIGNER_DB` and `THRESHOLD_STORE`.
8. Keep the Postgres signer database as an external read-only archive for 30
   days. Delete all direct legacy Postgres runtime paths; keep only the
   Postgres signer adapter and its migrations, contract tests, and tenant-route
   migration tooling.

## Sponsored EVM Gas Payments

Keep the production feature:

```text
Client sends publishable-key sponsored EVM call.
Seams verifies origin, API credential, environment, runtime policy, and spend cap.
Seams submits the EVM transaction through a configured sponsor executor.
Seams settles prepaid billing and writes reconciliation evidence.
Dashboard shows sponsored execution history, prepaid charges, and exceptions.
```

Simplify the storage model:

- Use the active `ConsoleBillingStore` as the source of truth for sponsored
  execution records. The first-release route stores these records in D1.
- Use an append-only billing ledger table.
- Use prepaid reservation summaries for fast balance reads.
- Use source-event IDs and idempotency keys as unique constraints.
- Store execution record, prepaid settlement event, and ledger debit in one
  backend transaction when post-execution settlement is finalized. The D1 adapter
  uses one `D1Database.batch()`; the Postgres adapter uses one transaction.
- Store a request digest for every idempotency key and reject digest mismatch.
- Treat external EVM submission as the only non-transactional boundary. Persist a
  sponsored execution record before submission, then finalize billing from that
  record after the receipt is available.

Required tables:

```sql
CREATE TABLE console_sponsored_executions (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  chain_family TEXT NOT NULL,
  intent_kind TEXT NOT NULL,
  execution_status TEXT NOT NULL,
  settlement_status TEXT NOT NULL,
  sponsor_ref TEXT NOT NULL,
  target_ref TEXT NOT NULL,
  receipt_status TEXT NOT NULL,
  charged INTEGER NOT NULL,
  charged_reason TEXT,
  estimated_spend_minor INTEGER,
  settled_spend_minor INTEGER,
  billing_ledger_entry_id TEXT,
  prepaid_reservation_id TEXT,
  tx_or_execution_ref TEXT,
  details_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, idempotency_key),
  CHECK (execution_status IN (
    'reserved',
    'submitted',
    'receipt_pending',
    'receipt_succeeded',
    'receipt_failed'
  )),
  CHECK (settlement_status IN (
    'reservation_active',
    'settlement_required',
    'settled',
    'released',
    'reconciliation_required'
  ))
);
```

```sql
CREATE TABLE console_billing_ledger_entries (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  type TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  wallet_id TEXT,
  tx_or_execution_ref TEXT,
  metadata_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, id),
  UNIQUE (namespace, org_id, source_event_id)
);
```

Settlement invariants:

- A successful charged sponsored execution has exactly one ledger debit.
- A released zero-spend execution has no ledger debit and records a release
  reason.
- A retry with the same idempotency key returns the existing sponsored execution.
- A retry with the same idempotency key and different request digest fails.
- Reconciliation pages derive from sponsored executions plus ledger entries.

Settlement state:

```ts
type SponsoredExecutionSettlement =
  | {
      kind: 'reserved';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      requestDigest: RequestDigest;
    }
  | {
      kind: 'submitted';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      executorSubmissionRef: ExternalExecutionRef;
      requestDigest: RequestDigest;
    }
  | {
      kind: 'receipt_pending';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      executorSubmissionRef: ExternalExecutionRef;
      requestDigest: RequestDigest;
    }
  | {
      kind: 'settled';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      billingLedgerEntryId: BillingLedgerEntryId;
      settledSpendMinor: MinorUnits;
      requestDigest: RequestDigest;
    }
  | {
      kind: 'released';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      releasedReason: SponsoredReleaseReason;
      requestDigest: RequestDigest;
    }
  | {
      kind: 'reconciliation_required';
      sponsoredExecutionId: SponsoredExecutionId;
      prepaidReservationId: PrepaidReservationId;
      executorSubmissionRef: ExternalExecutionRef;
      requestDigest: RequestDigest;
      lastErrorCode: SponsoredSettlementErrorCode;
    };
```

Sponsored write sequence:

1. Normalize tenant, API credential, idempotency key, and request digest.
2. Read existing execution by `(namespace, org_id, idempotency_key)`.
3. Return the existing execution when the digest matches. Return
   `idempotency_conflict` when it differs.
4. Reserve prepaid balance through `ConsolePrepaidReservationStore`.
5. Insert a `reserved` sponsored execution that references the reservation.
6. Submit the EVM call through the sponsor executor.
7. Update the sponsored execution to `submitted` or `receipt_pending` as soon as
   an external submission reference exists.
8. After the receipt is final, call
   `ConsoleBillingStore.finalizeSponsoredExecution()`. The D1 adapter runs one
   `D1Database.batch()` that updates the reservation lifecycle, writes the ledger
   debit when charged, and updates the sponsored execution to `settled` or
   `released`. The Postgres adapter performs the same transition in one
   transaction.
9. If the final batch fails after external submission, retries resume from the
   `submitted` or `receipt_pending` record. Unique ledger `source_event_id` and
   reservation lifecycle checks make finalization idempotent.
10. A scheduled reconciler scans `receipt_pending` and `reconciliation_required`
    executions and reruns finalization by idempotency key.

## Billing Reservations

Replace `FOR UPDATE` row locking with atomic D1/SQLite reservation lifecycle.

Required direction:

- Use the active `ConsoleBillingStore` as the source of truth for prepaid
  reservations and summary balances.
- Use SQLite atomicity for every D1 reservation lifecycle transition.
- Use Postgres transactions and row locks for every Postgres reservation
  lifecycle transition.
- Implement reserve as a reservation `INSERT` with a `BEFORE INSERT` trigger
  that debits `console_prepaid_summaries`.
- Duplicate `source_event_id` attempts must fail the reservation insert and roll
  back trigger side effects in the same SQLite statement.
- Implement settle and release as reservation lifecycle `UPDATE` statements with
  triggers that update summaries and append events.
- Use `D1Database.batch()` when a D1 lifecycle transition must update
  reservation, sponsored execution, and ledger rows together. Use one Postgres
  transaction for the same multi-record transition in the Postgres adapter.
- No prepaid reservation path may perform an unguarded summary mutation and then
  rely on a later database call for idempotency. The D1 reserve path uses one
  trigger-backed `INSERT`; the Postgres reserve path uses one transaction with
  row locks and unique idempotency keys.

Tables:

```sql
CREATE TABLE console_prepaid_summaries (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  available_minor INTEGER NOT NULL,
  reserved_minor INTEGER NOT NULL,
  settled_minor INTEGER NOT NULL,
  active_reservation_count INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id),
  CHECK (available_minor >= 0),
  CHECK (reserved_minor >= 0),
  CHECK (settled_minor >= 0),
  CHECK (active_reservation_count >= 0)
);
```

```sql
CREATE TABLE console_prepaid_reservations (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  requested_minor INTEGER NOT NULL,
  settled_minor INTEGER NOT NULL,
  released_minor INTEGER NOT NULL,
  status TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, reservation_id),
  UNIQUE (namespace, org_id, source_event_id),
  CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED')),
  CHECK (requested_minor > 0),
  CHECK (settled_minor >= 0),
  CHECK (released_minor >= 0)
);
```

```sql
CREATE TABLE console_prepaid_reservation_events (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  reservation_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  amount_minor INTEGER NOT NULL,
  record_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, reservation_id, event_kind),
  CHECK (event_kind IN ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED'))
);
```

Reservation lifecycle triggers:

```sql
CREATE TRIGGER console_prepaid_reserve_insert
BEFORE INSERT ON console_prepaid_reservations
WHEN NEW.status = 'RESERVED'
BEGIN
  UPDATE console_prepaid_summaries
     SET available_minor = available_minor - NEW.requested_minor,
         reserved_minor = reserved_minor + NEW.requested_minor,
         active_reservation_count = active_reservation_count + 1,
         updated_at_ms = NEW.created_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND available_minor >= NEW.requested_minor;

  SELECT RAISE(ABORT, 'insufficient_prepaid_balance')
    WHERE changes() != 1;
END;

CREATE TRIGGER console_prepaid_reserve_event
AFTER INSERT ON console_prepaid_reservations
WHEN NEW.status = 'RESERVED'
BEGIN
  INSERT INTO console_prepaid_reservation_events (
    namespace,
    org_id,
    reservation_id,
    event_kind,
    source_event_id,
    amount_minor,
    record_json,
    created_at_ms
  )
  VALUES (
    NEW.namespace,
    NEW.org_id,
    NEW.reservation_id,
    'RESERVED',
    NEW.source_event_id,
    NEW.requested_minor,
    '{}',
    NEW.created_at_ms
  );
END;
```

```sql
CREATE TRIGGER console_prepaid_reservation_settle
BEFORE UPDATE OF status ON console_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'SETTLED'
BEGIN
  SELECT RAISE(ABORT, 'invalid_settlement_amount')
    WHERE NEW.settled_minor < 0 OR NEW.settled_minor > OLD.requested_minor;

  UPDATE console_prepaid_summaries
     SET reserved_minor = reserved_minor - OLD.requested_minor,
         settled_minor = settled_minor + NEW.settled_minor,
         available_minor = available_minor + (OLD.requested_minor - NEW.settled_minor),
         active_reservation_count = active_reservation_count - 1,
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND reserved_minor >= OLD.requested_minor
     AND active_reservation_count > 0;

  SELECT RAISE(ABORT, 'corrupt_prepaid_summary')
    WHERE changes() != 1;
END;

CREATE TRIGGER console_prepaid_reservation_release
BEFORE UPDATE OF status ON console_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status IN ('RELEASED', 'EXPIRED')
BEGIN
  UPDATE console_prepaid_summaries
     SET reserved_minor = reserved_minor - OLD.requested_minor,
         available_minor = available_minor + OLD.requested_minor,
         active_reservation_count = active_reservation_count - 1,
         updated_at_ms = NEW.updated_at_ms
   WHERE namespace = NEW.namespace
     AND org_id = NEW.org_id
     AND reserved_minor >= OLD.requested_minor
     AND active_reservation_count > 0;

  SELECT RAISE(ABORT, 'corrupt_prepaid_summary')
    WHERE changes() != 1;
END;
```

```sql
CREATE TRIGGER console_prepaid_settle_event
AFTER UPDATE OF status ON console_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status = 'SETTLED'
BEGIN
  INSERT INTO console_prepaid_reservation_events (
    namespace,
    org_id,
    reservation_id,
    event_kind,
    source_event_id,
    amount_minor,
    record_json,
    created_at_ms
  )
  VALUES (
    NEW.namespace,
    NEW.org_id,
    NEW.reservation_id,
    'SETTLED',
    NEW.source_event_id,
    NEW.settled_minor,
    '{}',
    NEW.updated_at_ms
  );
END;

CREATE TRIGGER console_prepaid_release_event
AFTER UPDATE OF status ON console_prepaid_reservations
WHEN OLD.status = 'RESERVED' AND NEW.status IN ('RELEASED', 'EXPIRED')
BEGIN
  INSERT INTO console_prepaid_reservation_events (
    namespace,
    org_id,
    reservation_id,
    event_kind,
    source_event_id,
    amount_minor,
    record_json,
    created_at_ms
  )
  VALUES (
    NEW.namespace,
    NEW.org_id,
    NEW.reservation_id,
    NEW.status,
    NEW.source_event_id,
    OLD.requested_minor,
    '{}',
    NEW.updated_at_ms
  );
END;
```

Reserve flow:

- Read an existing reservation by `(namespace, org_id, source_event_id)`.
- If one exists with the same request digest, return it.
- If one exists with a different request digest, return `idempotency_conflict`.
- Insert the reservation with `status = 'RESERVED'`. The insert trigger debits
  the summary and appends the reserve event.
- If the insert fails with `insufficient_prepaid_balance`, return that typed
  failure.
- If the insert hits the unique source-event constraint after a concurrent
  request, read the existing row and apply the same digest comparison.

Settle flow:

- Read reservation by `(namespace, org_id, source_event_id)`.
- If already settled with the same amount, return it.
- If already settled with a different amount, return an idempotency conflict.
- If released or expired, return an invalid lifecycle transition.
- Update reservation from `RESERVED` to `SETTLED` with `WHERE status =
  'RESERVED' AND request_digest = ?`. The trigger updates the summary and
  appends the settle event.
- If the update changes zero rows, re-read the reservation and classify the
  result as idempotent success, idempotency conflict, or lifecycle failure.

Release flow:

- Read reservation by `(namespace, org_id, source_event_id)`.
- If already released with the same digest, return it.
- If settled, return an invalid lifecycle transition.
- Update reservation from `RESERVED` to `RELEASED` with `WHERE status =
  'RESERVED' AND request_digest = ?`. The trigger updates the summary and
  appends the release event.
- If the update changes zero rows, re-read and classify the result.

Postgres reserve flow:

- Start a transaction.
- Read an existing reservation by `(namespace, org_id, source_event_id)`.
- Return the existing reservation when the digest matches. Return
  `idempotency_conflict` when it differs.
- Lock the prepaid summary row with `FOR UPDATE`.
- Verify `available_minor >= requested_minor`.
- Insert the reservation, insert the reserve event, and update the summary in
  the same transaction.
- Commit and return the typed reservation result.
- On a unique source-event violation, roll back, read the existing reservation,
  and apply the same digest comparison.

Postgres settle and release flows:

- Start a transaction.
- Lock the reservation row and prepaid summary row with `FOR UPDATE`.
- Apply the same lifecycle checks as the D1 adapter.
- Update reservation, append the lifecycle event, update the summary, and write
  any sponsored ledger entry in the same transaction.
- Commit and return the same result union used by the D1 adapter.

The reservation implementation ships only after local and remote D1 tests prove
the trigger-backed insert is atomic. A duplicate source-event insert must leave
`available_minor`, `reserved_minor`, and `active_reservation_count` unchanged.

Validation:

- concurrent reservations cannot overdraw available balance
- duplicate source-event reserve returns the same reservation
- duplicate reserve cannot debit the summary twice
- duplicate reserve that hits the unique constraint rolls back all trigger side
  effects
- duplicate settle with the same amount is idempotent
- duplicate settle with a different amount fails
- release after settle fails
- settle after release fails
- reservation event count matches reservation lifecycle transitions

## Runtime Snapshot Outbox

Replace `FOR UPDATE SKIP LOCKED` with leases.

Tables:

```sql
CREATE TABLE console_runtime_snapshot_outbox (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  snapshot_version INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  claimed_by TEXT,
  claim_expires_at_ms INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_visible_at_ms INTEGER,
  last_error_code TEXT,
  last_error_message TEXT,
  dead_lettered_at_ms INTEGER,
  dispatched_at_ms INTEGER,
  PRIMARY KEY (namespace, org_id, event_id),
  UNIQUE (namespace, org_id, snapshot_id, snapshot_version, event_type)
);

CREATE INDEX console_runtime_snapshot_outbox_pending_idx
  ON console_runtime_snapshot_outbox (
    namespace,
    org_id,
    dispatched_at_ms,
    claim_expires_at_ms,
    created_at_ms
  );
```

Claim flow:

1. Select candidate IDs where `dispatched_at_ms IS NULL` and the claim is empty
   or expired, `dead_lettered_at_ms IS NULL`, and `next_visible_at_ms IS NULL OR
   next_visible_at_ms <= now`.
2. For each candidate, run a conditional update:

```sql
UPDATE console_runtime_snapshot_outbox
   SET claimed_by = ?,
       claim_expires_at_ms = ?,
       attempt_count = attempt_count + 1
 WHERE namespace = ?
   AND org_id = ?
   AND event_id = ?
   AND dispatched_at_ms IS NULL
   AND dead_lettered_at_ms IS NULL
   AND (next_visible_at_ms IS NULL OR next_visible_at_ms <= ?)
   AND (claimed_by IS NULL OR claim_expires_at_ms <= ?);
```

3. Read rows claimed by the worker ID.
4. Dispatch each event.
5. Mark successful events with `dispatched_at_ms`.
6. Mark failed events with `last_error_code`, `last_error_message`, cleared
   claim fields, and `next_visible_at_ms` using exponential backoff capped at one
   hour.
7. Move events to dead letter after 25 failed attempts by setting
   `dead_lettered_at_ms`.

Use `UPDATE ... RETURNING` only after it is verified in local D1 and remote D1.
The portable baseline is conditional `UPDATE`, check `changes`, then `SELECT`.

Postgres outbox claiming may use a single transaction with `FOR UPDATE SKIP
LOCKED`. It must honor the same lease, retry, backoff, and dead-letter fields.

Validation:

- two dispatchers cannot claim the same event inside the lease window
- expired leases are claimable
- dispatched events are never claimed again
- failed dispatch leaves the event retryable after lease expiry
- retry backoff delays visibility until `next_visible_at_ms`
- events dead-letter after the configured attempt limit
- D1 and Postgres adapters return the same claim and retry result unions

## Console Observability

D1 can hold low-to-moderate dashboard observability data. It should not become
one large raw event warehouse.

Plan:

- Keep redacted events in D1 for the configured retention window when volume is
  low.
- Store request rollups as the primary dashboard query surface.
- Batch retention deletes in small chunks.
- Move high-volume raw logs to Cloudflare Logs/R2/Analytics Engine when event
  volume approaches D1 limits.

First-release operating envelope:

- Request rollups stay in D1 for 400 days.
- Redacted raw events stay in D1 for 7 days.
- Raw events stay enabled only while the console database remains below 7 GB,
  raw observability rows remain below 1,000,000 rows, and sustained raw event
  writes remain below 25 rows per second for the whole database.
- Any tenant that exceeds 100,000 raw rows in a 24 hour period moves to rollups
  only in D1, with raw events routed to Analytics Engine, R2, or Cloudflare Logs.
- Retention cleanup deletes at most 500 rows per statement and runs until the
  expired backlog is below 10,000 rows.
- Alert at 70 percent of any storage, row-count, or write-rate threshold.

Schema replacement:

- Replace Postgres partitions with month bucket columns and indexes.
- Replace JSONB metadata with `metadata_json TEXT`.
- Parse and validate metadata at read boundaries.
- Keep all dashboard filters index-backed.

## Preparation Decisions Before Refactor

Resolve these before changing production code paths.

### 1. Refactor Order

Use this order:

1. Add storage route and store factory types.
2. Add D1/DO adapter interfaces and row parsers.
3. Add Postgres adapter interfaces behind the same ports.
4. Add local Wrangler D1/DO runtime and migration scripts.
5. Port signer metadata and sealed ciphertext.
6. Port signer coordination to Durable Objects.
7. Port console domains, billing, sponsored settlement, and runtime snapshots.
8. Add tenant route migration tooling.
9. Cut over bootstrap from direct Postgres URLs to resolved route stores.
10. Delete direct legacy Postgres and memory production-adjacent paths.

Reason: this makes the route/store boundary the first invariant, so individual
domain ports can move without changing route handlers repeatedly.

### 2. Signer Table Ownership Inventory

Current local `seams_signer` tables map as follows:

| Current Postgres table | Target owner | Notes |
| --- | --- | --- |
| `app_session_versions` | D1 metadata | queryable auth/session metadata |
| `device_linking_sessions` | D1 metadata with TTL | dashboard/support lookup plus expiry |
| `email_otp_auth_states` | D1 metadata with TTL | OTP lifecycle state |
| `email_otp_challenges` | D1 metadata with TTL | challenge state |
| `email_otp_grants` | D1 metadata | grant/reconciliation state |
| `email_otp_recovery_wrapped_enrollment_escrows` | D1 metadata | encrypted escrow metadata |
| `email_otp_registration_attempts` | D1 metadata with TTL | registration attempt state |
| `email_otp_unlock_challenges` | D1 metadata with TTL | challenge state |
| `email_otp_wallet_enrollments` | D1 metadata | wallet auth metadata |
| `email_recovery_preparations` | D1 metadata with TTL | recovery preparation state |
| `identity_links` | D1 metadata | queryable identity indexes |
| `near_public_keys` | D1 metadata | wallet/key lookup |
| `recovery_executions` | D1 metadata | recovery audit/reconciliation |
| `recovery_sessions` | D1 metadata with TTL | recovery lifecycle |
| `router_ab_normal_signing_abuse_records` | D1 metadata with TTL | admission-control evidence |
| `router_ab_normal_signing_project_policies` | D1 metadata | signing admission policy |
| `router_ab_normal_signing_quota_reservations` | Durable Object coordination | hot quota reservation state |
| `signing_root_secret_shares` | D1 sealed ciphertext | encrypted share records only |
| `threshold_ecdsa_keys` | D1 metadata | threshold key metadata and identity indexes |
| `threshold_ecdsa_presign_sessions` | Durable Object coordination | hot pool-fill/session state |
| `threshold_ecdsa_presignatures` | Durable Object coordination | presignature pool inventory |
| `threshold_ecdsa_signing_sessions` | Durable Object coordination | active signing lifecycle |
| `threshold_ed25519_auth_consumptions` | Durable Object coordination | idempotent consumption guard |
| `threshold_ed25519_keys` | D1 metadata | threshold key metadata |
| `threshold_ed25519_sessions` | Durable Object coordination | active signing lifecycle |
| `threshold_wallet_session_budget_reservations` | Durable Object coordination | budget reserve/commit/release |
| `threshold_wallet_session_consumptions` | Durable Object coordination | use-count consumption guard |
| `wallet_auth_methods` | D1 metadata | wallet auth lookup |
| `wallet_registration_ceremonies` | D1 metadata with TTL | registration lifecycle |
| `wallet_registration_intents` | D1 metadata with TTL | registration intent lifecycle |
| `wallet_signers` | D1 metadata | wallet signer lookup |
| `wallets` | D1 metadata | wallet primary records |
| `webauthn_authenticators` | D1 metadata | authenticator lookup |
| `webauthn_challenges` | D1 metadata with TTL | challenge state |
| `webauthn_credential_bindings` | D1 metadata | credential lookup |

No signer table is marked obsolete in the first migration pass. Delete a table
only after the importing code, fixtures, and production inventory prove that its
state is no longer part of the current product.

### 3. Tenant Identity For Signer Rows

Decision:

- Every signer D1 row includes `namespace` and `org_id`.
- Wallet-scoped rows include `project_id`, `env_id`, and `wallet_id`.
- Signing-root and sealed-share rows include `project_id`, `env_id`,
  `signing_root_id`, and `signing_root_version`.
- Durable Object names include `namespace` and the coordination atom. The DO
  stored rows also include `org_id` when the row is durable beyond one request.
- Migration tooling must map legacy signer rows to `org_id`, `project_id`, and
  `env_id` before import.
- Rows that cannot be mapped to tenant identity fail migration and require an
  explicit migration manifest entry.

Reason: tenant isolation must be a persisted invariant, not an assumption
derived from the route that happened to read the row.

### 4. Production Cutover Source Of Truth

Create a checked-in cutover manifest template before implementation:

```ts
type D1CutoverSourceManifest = {
  environment: 'staging' | 'production';
  signerPostgres: {
    logicalDatabase: 'seams_signer';
    runtimeSecretName: 'POSTGRES_URL';
    migrationSecretName: 'POSTGRES_MIGRATION_URL';
    readOnlyArchiveDays: 30;
  };
  consolePostgres: {
    logicalDatabase: 'seams_console';
    runtimeSecretName: 'CONSOLE_POSTGRES_URL';
    migrationSecretName: 'CONSOLE_POSTGRES_MIGRATION_URL';
    readOnlyArchiveDays: 30;
  };
  targetCloudflare: {
    consoleDatabaseName: 'seams-console';
    signerDatabaseName: 'seams-signer';
    tenantRouteDatabaseName: 'seams-tenant-routes';
    thresholdStoreBinding: 'THRESHOLD_STORE';
    backupBucketName: 'seams-d1-backups';
  };
  cutover: {
    freezeWindowIso: string;
    operator: string;
    rollbackOwner: string;
  };
};
```

The real production URLs, Cloudflare account IDs, and operator names stay out of
the repository. They are supplied through secret managers and the release
runbook.

### 5. Backup Infrastructure Names

Recommended defaults:

- R2 bucket: `seams-d1-backups`
- Backup writer token: `SEAMS_D1_BACKUP_WRITER`
- Backup restore token: `SEAMS_D1_BACKUP_RESTORE`
- Export prefix:
  `env/{environment}/database/{databaseName}/year={yyyy}/month={mm}/day={dd}/{timestamp}_{routeKind}_rv{routeVersion}_sv{schemaVersion}_{bookmark}.sql`
- Metadata sidecar prefix:
  `env/{environment}/database/{databaseName}/year={yyyy}/month={mm}/day={dd}/{timestamp}_{routeKind}_rv{routeVersion}_sv{schemaVersion}_{bookmark}.json`

Each metadata sidecar records source database name, route kind, route version,
schema version, Time Travel bookmark, export command version, row counts, signer
sealed-share counts, and billing totals.

## Migration Phases

### Phase 0: Inventory And Cut Line

- [ ] List every `createPostgresConsole*Service` and owning route surface.
- [ ] List every signer-domain Postgres table owned by `ensurePostgresSchema`.
- [ ] Classify each signer table as D1 metadata, D1 sealed ciphertext, Durable
      Object coordination state, or deleted obsolete state.
- [ ] Mark each in-memory console service as test/demo only.
- [ ] Confirm the production cut line: D1/DO becomes the default active backend,
      direct legacy Postgres service paths are deleted, and Postgres remains
      available only through adapter ports.
- [ ] Use shared console D1 and shared signer D1 for the first release.
- [ ] Keep enterprise database-per-tenant isolation as a post-cutover scaling
      option.
- [ ] Add `TenantStorageRoute` as the routing boundary for future tenant moves.
- [ ] Document tenant move triggers: 2 GB tenant size, 30 percent shared DB
      share, 7 GB shared DB alert, 8 GB move/offload preparation, and 9 GB
      high-volume write freeze.
- [ ] Confirm Postgres is the large-limit backend adapter when D1 sharding would
      create excessive query or operational complexity.
- [ ] Keep redacted raw observability in D1 only inside the first-release
      operating envelope.
- [ ] Confirm D1 Time Travel is the primary 30-day recovery layer and weekly R2
      exports are the long-retention backup layer.

### Phase 1: D1 Runtime And Local Development

- [ ] Add `wrangler.toml` D1 binding for `CONSOLE_DB`.
- [ ] Add `wrangler.toml` D1 binding for `SIGNER_DB`.
- [ ] Add `THRESHOLD_STORE` Durable Object binding with `new_sqlite_classes`.
- [ ] Add optional Hyperdrive binding examples for the Postgres backend adapter.
- [ ] Validate final Wrangler config with `pnpm wrangler types` and
      `pnpm wrangler deploy --dry-run`.
- [ ] Add `migrations/d1`, `migrations/d1-signer`, and first schema migrations.
- [ ] Add scripts:
      `console:d1:migrate:local`,
      `console:d1:migrate:remote`,
      `console:d1:query:local`,
      `console:d1:dev`,
      `signer:d1:migrate:local`,
      `signer:d1:migrate:remote`,
      `signer:d1:query:local`,
      `postgres:adapter:test`.
- [ ] Add a documented `wrangler dev --persist-to .wrangler/state/seams-d1`
      workflow for stable local D1/DO state and TablePlus inspection.
- [ ] Update local server docs to remove the Postgres Docker dependency for the
      console and signer paths.
- [ ] Add Workers Vitest configuration for D1-backed and DO-backed integration
      tests.
- [ ] Add scripts for D1 Time Travel bookmark capture and weekly D1 export to
      R2 for `CONSOLE_DB`, `SIGNER_DB`, `TENANT_ROUTE_DB`, and dedicated tenant
      D1 databases.

### Phase 2: D1 Storage Boundary

- [ ] Add `ConsoleD1Database` and `ConsoleD1PreparedStatement` types.
- [ ] Add `SignerD1Database` and signer row parser types.
- [ ] Add `ConsolePostgresPool`, `SignerPostgresPool`, and Hyperdrive runtime
      target types.
- [ ] Add `TenantStorageRoute` and shared-route resolver.
- [ ] Add `TENANT_ROUTE_DB` route and migration schemas, parsers,
      compare-and-set route switch helper, and route schema-version checks before
      any non-shared route ships.
- [ ] Add domain-level storage ports for prepaid reservations, sponsored
      executions, runtime snapshot outbox, and tenant-scoped console records.
- [ ] Add domain-level signer storage ports for wallet auth, WebAuthn, email OTP,
      threshold keys, sealed share ciphertext, recovery records, and session
      coordination.
- [ ] Add D1 row parsers for `TEXT` JSON, integer booleans, timestamps, and enum
      columns.
- [ ] Add strict tenant context type required by every storage-backed service
      method.
- [ ] Add `SignerTenantContext` with wallet and custody branches.
- [ ] Add type fixtures rejecting optional tenant identity and raw row use in
      domain logic.
- [ ] Add guard tests proving core services do not import D1 or Postgres driver
      types directly.
- [ ] Add guard tests proving console routes cannot import signer KEK bindings.
- [ ] Add guard tests proving storage methods receive a resolved
      `TenantStorageRoute` and cannot accept raw binding names from requests.
- [ ] Add type fixtures proving invalid route/backend combinations cannot be
      constructed.
- [ ] Add adapter contract tests that run the same store behavior against D1 and
      Postgres.

### Phase 3: Core Console Domains

- [ ] Port org/project/environment to D1.
- [ ] Implement Postgres adapter stores for org/project/environment.
- [ ] Port account profiles and backup emails to D1.
- [ ] Implement Postgres adapter stores for account profiles and backup emails.
- [ ] Port team RBAC to D1 with explicit role arrays encoded as JSON text.
- [ ] Port policies and policy versions to D1.
- [ ] Port approvals to D1.
- [ ] Port API keys and bootstrap tokens to D1.
- [ ] Port audit events to D1.
- [ ] Port wallets and sponsored call indexes to D1.
- [ ] Implement Postgres adapter stores for RBAC, policies, approvals, API keys,
      audit events, wallets, and sponsored call indexes.

### Phase 4: Signer Metadata And Sealed Ciphertext

- [ ] Port WebAuthn authenticators, credential bindings, and challenges to D1.
- [ ] Implement Postgres adapter stores for WebAuthn records.
- [ ] Port wallet registration intents and ceremonies to D1.
- [ ] Port wallets, wallet auth methods, and wallet signers to D1.
- [ ] Port email OTP challenges, grants, enrollments, recovery escrows, auth
      state, unlock challenges, and registration attempts to D1.
- [ ] Port threshold Ed25519 and ECDSA key metadata to D1.
- [ ] Port ECDSA identity uniqueness through base and identity tables.
- [ ] Port sealed signing-root share ciphertext to D1 with required
      `kek_id`, `envelope_version`, AAD digest, ciphertext digest, rotation
      state, and audit event fields.
- [ ] Port device-linking, email recovery, near public key, identity link,
      app-session version, recovery session, and recovery execution records to
      D1.
- [ ] Implement Postgres adapter stores for signer metadata and sealed signer
      ciphertext.
- [ ] Add signer migration fixtures proving malformed sealed records fail at the
      read boundary.
- [ ] Add secret-boundary tests proving plaintext shares and KEKs are never
      written to D1.
- [ ] Add KEK migration manifest checks for rows that lack `kek_id`.

### Phase 5: Signer Durable Objects

- [ ] Move signing-session use counters and idempotency consumption guards to
      `THRESHOLD_STORE`.
- [ ] Move wallet signing budget reserve/commit/release/validate to
      `THRESHOLD_STORE`.
- [ ] Move ECDSA presignature put/reserve/take/discard to `THRESHOLD_STORE`.
- [ ] Move ECDSA pool-fill session CAS advancement to `THRESHOLD_STORE`.
- [ ] Move Ed25519 presign capacity and rate-limit state to `THRESHOLD_STORE`.
- [ ] Move signing-root status and replay guards to `THRESHOLD_STORE`.
- [ ] Implement Postgres adapter stores for signer coordination using
      transactions, row locks, and idempotency indexes.
- [ ] Add deterministic object names for wallet, signing-root, relayer-key, and
      session coordination atoms.
- [ ] Convert `ThresholdStoreDurableObject` to SQLite-backed storage and typed
      RPC methods.
- [ ] Add DO SQL schema setup in the constructor and keep
      `blockConcurrencyWhile()` scoped to initialization.
- [ ] Add DO alarm cleanup for expired reservations, replay guards, and
      presignature reservations where useful.
- [ ] Delete any import-only fetch route before production cutover.

### Phase 6: Billing And Sponsored Gas

- [ ] Add D1 prepaid summaries, reservations, reservation events, ledger entries,
      and sponsored execution tables.
- [ ] Add Postgres adapter schema for prepaid summaries, reservations,
      reservation events, ledger entries, and sponsored executions.
- [ ] Implement atomic D1/SQLite prepaid reservation lifecycle.
- [ ] Implement Postgres prepaid reservation lifecycle with transactions and row
      locks.
- [ ] Validate prepaid triggers against local D1 and remote D1.
- [ ] Add a duplicate-reserve unique-conflict test proving summary balances are
      unchanged after the failed insert.
- [ ] Implement idempotent settlement and release flows.
- [ ] Implement sponsored execution request-digest idempotency and settlement
      state machine.
- [ ] Implement sponsored EVM post-execution finalization through
      `ConsoleBillingStore.finalizeSponsoredExecution()`, with one D1 `batch()`
      or one Postgres transaction.
- [ ] Add scheduled reconciliation for `receipt_pending` and
      `reconciliation_required` executions.
- [ ] Replace the startup Postgres requirement for sponsored EVM with active
      billing storage readiness checks.
- [ ] Update dashboard sponsored execution and reconciliation routes to read
      through the active billing store.
- [ ] Run billing adapter contract tests against both D1 and Postgres.

### Phase 7: Runtime Snapshots And Outbox

- [ ] Port runtime snapshots to D1.
- [ ] Implement Postgres runtime snapshot adapter behind the same store port.
- [ ] Add outbox lease columns and indexes.
- [ ] Add outbox retry, backoff, and dead-letter columns.
- [ ] Implement claim/read/dispatch/mark-dispatched flow.
- [ ] Implement dispatch failure handling with retry backoff and dead-letter
      classification.
- [ ] Add lease expiry tests with two concurrent dispatchers.
- [ ] Delete `FOR UPDATE SKIP LOCKED` expectations from tests and fixtures.

### Phase 8: Observability

- [ ] Port request rollups to D1.
- [ ] Port redacted raw events only if expected volume fits the D1 operating
      envelope.
- [ ] Add retention cleanup that deletes in batches.
- [ ] Route larger raw event storage to a non-D1 service when needed.
- [ ] Add alerts for 70 percent of the D1 observability operating envelope.

### Phase 9: Cutover And Cleanup

- [ ] Switch app bootstrap from `CONSOLE_POSTGRES_URL` to `CONSOLE_DB` binding.
- [ ] Switch signer bootstrap from `POSTGRES_URL` signer tables to `SIGNER_DB`
      and `THRESHOLD_STORE`.
- [ ] Delete `CONSOLE_*_BACKEND=postgres` code paths.
- [ ] Delete direct legacy Postgres code paths after adapter cutover.
- [ ] Keep Postgres adapter migrations and contract tests.
- [ ] Delete obsolete Postgres-specific console and signer tests and fixtures
      that bypass the adapter ports.
- [ ] Keep `pg` owned by the Postgres adapter package. Remove direct `pg`
      imports from routes and domain services.
- [ ] Keep original Postgres databases as external read-only archives for 30
      days without direct legacy runtime code paths.
- [ ] Document tenant-scoped restore, delete, tenant move, Time Travel restore,
      R2 export, and R2 restore runbooks.

## Data Migration

Use export/import tooling at the persistence boundary. Separate one-time default
cutover scripts from reusable tenant-route migration tooling.

Default import tooling:

- D1 schema changes use Wrangler migrations.
- D1 data imports use repository scripts that parse Postgres JSONL into internal
  domain types, then write through `D1Database.batch()` in bounded chunks.
- Postgres schema changes use adapter-owned migrations.
- Postgres imports write through Postgres adapters, not raw SQL import shortcuts.
- Remote D1 imports capture `wrangler d1 time-travel info` output before and
  after import.
- Remote D1 imports write a post-import R2 export before production cutover.
- DO imports use a separate one-time migration Worker bound to `THRESHOLD_STORE`
  and protected by a migration token. Delete that Worker and token after cutover.
- One-time Postgres-to-D1 cutover scripts live under `scripts/d1-cutover` and
  are deleted after production cutover and the 30 day read-only archive window.
- Reusable tenant route migration tooling lives under `scripts/tenant-routes`
  and stays in the repository. It supports D1-to-D1, D1/DO-to-Postgres, and
  Postgres-to-D1 test migrations through adapter ports.

Console flow:

1. Export Postgres console tables to normalized JSONL.
2. Parse each row into current internal domain types.
3. Write D1 import SQL or direct D1 batch import commands.
4. Compare record counts and aggregate balances.
5. Compare prepaid summary totals against reservation events and ledger entries.
6. Run reconciliation checks for billing and sponsored executions.
7. Freeze Postgres writes.
8. Apply final delta export.
9. Enable D1 console runtime.
10. Keep Postgres console databases as external read-only archives for 30 days.

Signer flow:

1. Export Postgres signer tables to normalized JSONL.
2. Parse each row into current internal domain types.
3. Import signer metadata and sealed ciphertext rows into `SIGNER_DB`.
4. Compare signer record counts and identity indexes.
5. Verify sealed share counts by signing root, version, and share ID.
6. Verify ciphertext digest, AAD digest, `kek_id`, envelope version, and audit
   event ID for every sealed share.
7. Verify wallet address, public key, relying-party, signing-root, and threshold
   key continuity.
8. Verify no plaintext secret fields appear in D1 or DO exports.
9. Disable new signer sessions, budget reservations, replay guards, and
   presignature reservations.
10. Wait for active session TTLs, reservation TTLs, replay guard TTLs, and
    presignature reservation TTLs to elapse.
11. Import available presignature inventory, signing-root status, and remaining
    hot coordination state into `THRESHOLD_STORE`.
12. Run signing, session-budget, and presignature parity tests.
13. Freeze Postgres signer writes.
14. Apply final signer metadata and DO activation imports.
15. Enable Worker runtime using `SIGNER_DB` and `THRESHOLD_STORE`.
16. Keep Postgres signer databases as external read-only archives for 30 days.

Rollback handling:

- Before runtime cutover, keep Postgres frozen and rerun import after fixing the
  failing D1/DO migration step.
- After runtime cutover, stop write ingress, capture current D1 bookmarks, export
  D1/DO state for investigation, restore D1 through Time Travel or reimport from
  Postgres archive, then rerun smoke tests before reopening writes.
- Runtime rollback can switch to Postgres only through `TenantStorageRoute` and
  adapter contract tests. Direct legacy Postgres service paths remain deleted.
- The 30 day Postgres archive exists for data recovery and support reads until a
  route is intentionally migrated to the Postgres adapter.

D1/DO to Postgres route migration:

1. Confirm the tenant meets a Postgres route trigger.
2. Provision Postgres, Hyperdrive, schema, and backup policy.
3. Apply Postgres adapter migrations.
4. Freeze writes through `TENANT_ROUTE_DB`.
5. Export all route-owned D1/DO state for the tenant: console metadata, signer
   metadata, sealed signer ciphertext, durable signer coordination state,
   billing, sponsored execution records, runtime snapshots, snapshot outbox, and
   reconciliation data.
6. Parse exports into internal domain types.
7. Import through Postgres adapters.
8. Run adapter contract tests, tenant smoke tests, record-count checks,
   billing-balance checks, signer ciphertext checks, snapshot outbox checks, and
   sponsored settlement reconciliation.
9. Switch the route registry to `postgres_large_tenant` with compare-and-set and
   a new `routeVersion`.
10. Reopen writes.
11. Keep the source D1/DO route read-only for the archive window.
12. Delete source rows and retire unused KEKs according to tenant deletion and
    custody policy.

Postgres to D1/DO test migration:

- Supported only for staging, disaster-recovery drills, and future product
  migrations where the target D1/DO route is confirmed below operating
  thresholds.
- Uses the same adapter ports and parity checks as D1/DO-to-Postgres migration.
- Requires a new routeVersion and the same write-freeze protocol.

## Validation

Static checks:

- Storage-backed service methods require `ConsoleTenantContext`.
- Signer service methods require `SignerTenantContext`.
- Storage factories require `TenantStorageRoute`.
- Storage factories accept D1/DO and Postgres targets through discriminated
  unions.
- `shared`, `dedicated_tenant`, and `tenant_shard` routes accept only D1/DO
  targets.
- `postgres_large_tenant` routes accept only Postgres targets.
- Mixed console/signer backend route objects fail with `@ts-expect-error`.
- Sealed share decrypt methods require the custody branch of
  `SignerTenantContext`.
- Domain services cannot accept raw storage rows.
- Domain services cannot import Postgres pool/client types.
- JSON text parser failures return typed storage errors.
- Invalid billing reservation lifecycle object literals fail with
  `@ts-expect-error`.
- Invalid sponsored execution settlement states fail with `@ts-expect-error`.
- Invalid signer secret record states fail with `@ts-expect-error`.
- Invalid ECDSA key identity branch combinations fail with `@ts-expect-error`.
- Signer service methods require explicit metadata storage or coordination
  storage by branch.
- Switch statements over persisted domain row state are exhaustive.
- Switch statements over storage backend target unions are exhaustive.
- Switch statements over `TenantStorageRoute` are exhaustive.

Unit tests:

- D1 row parsers reject malformed JSON and unknown enum values.
- Postgres row parsers reject malformed JSON and unknown enum values.
- prepaid reserve succeeds when balance is sufficient
- prepaid reserve fails without changing state when balance is insufficient
- duplicate reserve by source-event ID is idempotent
- duplicate reserve by source-event ID cannot double-debit the prepaid summary
- settle/release lifecycle rejects invalid transitions
- prepaid reservation triggers keep summary balances and event rows consistent
- sponsored execution retry returns the prior result
- sponsored execution retry with a different digest fails
- sponsored execution resumes finalization from `submitted` and `receipt_pending`
  states
- outbox claim leases prevent duplicate dispatch
- outbox lease expiry allows retry
- tenant-scoped queries cannot read records from another org
- tenant route version mismatch returns `tenant_route_changed`
- route registry rejects stale compare-and-set updates
- route registry rejects a target whose schema version is newer than the running
  adapter
- route registry rejects invalid backend target combinations
- D1 and Postgres prepaid reservation contract tests produce equivalent domain
  results
- D1 and Postgres sponsored settlement contract tests produce equivalent domain
  results
- D1 and Postgres snapshot outbox contract tests produce equivalent claim and
  retry behavior
- D1 and Postgres signer metadata and sealed ciphertext contract tests produce
  equivalent domain results
- D1/DO and Postgres signer coordination contract tests produce equivalent
  idempotency, budget, and presignature results
- signer D1 row parsers reject malformed JSON, unknown states, missing tenant
  identity, and missing key identity
- sealed signer share parser rejects missing `kek_id`, missing envelope version,
  duplicate share IDs, and plaintext-looking secret fields
- sealed signer share parser rejects missing ciphertext digest, AAD digest,
  rotation state, and audit event ID
- signer ECDSA key parser rejects base rows without an identity row
- signer ECDSA key writer rejects threshold and wallet identity on the same key
- signer DO use-count consumption is idempotent by key
- signer DO budget reserve/commit/release cannot over-consume remaining uses
- signer DO presignature reserve/take cannot double-spend one presignature
- signer DO replay guard rejects a reused operation while the guard is active
- signer DO SQL schema migration runs once and preserves existing rows

Integration tests:

- run D1 migrations locally through Wrangler
- run D1 trigger migrations locally through Wrangler
- run Postgres adapter migrations against local Postgres
- capture D1 Time Travel bookmarks before and after remote D1 migration dry runs
- export a D1 backup to R2 in staging and verify export metadata
- restore a staging D1 database from Time Travel and run tenant smoke tests
- import the latest R2 export into a new staging D1 database and run tenant
  smoke tests
- start Worker with local D1 bindings and local `THRESHOLD_STORE`
- start Worker with Hyperdrive/Postgres adapter bindings in adapter test mode
- run route-registry migration fixture from shared D1/DO to Postgres and verify
  the old `routeVersion` cannot write
- create org, project, environment, policy, and API key
- register wallet auth metadata into signer D1
- import sealed signing-root share ciphertext into signer D1
- execute signing flow through local Durable Object coordination
- reserve, commit, and release signing-session budget through DO storage
- reserve and consume an ECDSA presignature through DO storage
- perform sponsored EVM call through a mocked executor
- settle prepaid billing and verify dashboard reconciliation
- retry sponsored EVM finalization after simulated D1 batch failure
- create runtime snapshot and dispatch outbox event once
- run billing dashboard routes from D1
- run observability dashboard routes from D1 if observability remains in D1
- run signer migration import against Postgres JSONL fixtures and compare
  ciphertext digest, AAD digest, key identity, public key, and wallet address
  continuity
- run cutover drain test proving expired sessions, replay guards, reservations,
  and reserved presignatures are dropped
- run a D1-to-Postgres tenant route migration fixture and verify reads/writes use
  the Postgres adapter after `routeVersion` changes

Manual smoke:

```bash
pnpm wrangler d1 migrations apply seams-console --local
pnpm wrangler d1 migrations apply seams-signer --local
pnpm wrangler dev --persist-to .wrangler/state/seams-d1
```

Then verify:

- dashboard loads
- org/project/environment creation persists after restart
- sponsored EVM route rejects out-of-policy requests
- sponsored EVM route records successful mocked execution
- billing overview reflects prepaid debit
- reconciliation page shows the sponsored execution and ledger entry
- wallet registration persists signer metadata in local D1
- signing session use counts persist through local Durable Objects
- sealed signer ciphertext is present in D1 and KEKs are absent from D1
- TablePlus can inspect the local D1 SQLite files under the configured
  `--persist-to` directory while Wrangler is stopped

## First-Release Decisions

- Production uses one shared console D1 database and one shared signer D1
  database.
- Enterprise database-per-tenant isolation is a post-cutover scaling option.
- Every request resolves a `TenantStorageRoute`; the first release returns the
  `shared` branch for every tenant.
- Tenant-specific D1 routing is introduced when a tenant meets the dedicated
  tenant criteria in the multi-tenancy section.
- Postgres backend routing is introduced when D1 size, throughput, or query
  complexity makes D1 sharding the wrong model.
- Postgres adapters use Hyperdrive in Worker runtime and direct pools in
  migration tooling.
- Production uses one `THRESHOLD_STORE` namespace with deterministic object
  names.
- Separate DO namespaces are introduced only when measured throughput or
  operational ownership requires them.
- Sealed signing-root share ciphertext lives in signer D1 for the first release.
- Hosted production signer KEKs live in Cloudflare Secrets Store and are scoped
  to one org or one enterprise tenant by `kek_id`.
- Local development and self-host deployments may use Wrangler secrets for KEKs.
- Enterprise customer-managed KMS/HSM support is a later custody option behind
  `SignerKekProvider`.
- Redacted raw observability can stay in D1 only inside the first-release
  operating envelope.
- Dashboard API runtime becomes Cloudflare Worker primary. Node/Express remains
  only for unrelated development tooling until those paths are removed.
- D1 imports use repository migration scripts and D1 Worker bindings.
- DO imports use a separate one-time migration Worker bound to `THRESHOLD_STORE`.
- Postgres imports and runtime access go through Postgres adapters.
- Billing reservations use atomic D1/SQLite, with no Durable Object fallback in
  the first release.
- D1 Time Travel is the primary short-term recovery layer.
- Weekly D1 exports to R2 are the long-retention backup layer.
- Pre-migration D1 Time Travel bookmarks are mandatory for schema migrations,
  data imports, tenant moves, route switches, and destructive maintenance jobs.
- Direct legacy Postgres service paths are deleted after adapter cutover.
- Postgres stays as an external read-only archive for 30 days after cutover.
- Postgres remains available as an adapter-routed backend for larger-limit
  tenants and migration drills.

## Remaining Product Choices

- Choose the first high-volume raw observability destination before disabling D1
  raw events for a tenant. Recommendation: Analytics Engine for dashboard
  metrics, R2 for long-retention raw archives, Cloudflare Logs for operational
  log search.
- Choose customer-managed KMS/HSM integrations when an enterprise tenant requires
  custody outside hosted Cloudflare Secrets Store.

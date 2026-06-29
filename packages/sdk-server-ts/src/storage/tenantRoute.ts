import type { CloudflareDurableObjectNamespaceLike } from '../core/types';
import type { SigningRootKekProvider } from '../core/ThresholdService/signingRootKekProvider';
import type { OrgId } from '@shared/utils/domainIds';

export type { OrgId } from '@shared/utils/domainIds';

export type TenantStorageBackendFamily = 'cloudflare_d1_do' | 'postgres';
export type CloudflareTenantTopology = 'shared' | 'dedicated_tenant';
export type TenantDataJurisdiction = 'automatic' | 'wnam' | 'enam' | 'weur' | 'eeur' | 'apac';
export type PostgresMigrationReason =
  | 'd1_size_limit'
  | 'd1_throughput_limit'
  | 'logical_database_required';

export type NamespaceId = string;
export type RouteVersion = number;
export type D1BindingName = string;
export type D1DatabaseName = string;
export type DurableObjectBindingName = string;
export type HyperdriveBindingName = string;
export type PostgresSchemaName = string;

export interface D1ResultLike<T = unknown> {
  readonly results?: readonly T[];
  readonly success: boolean;
  readonly meta?: {
    readonly changes?: number;
    readonly last_row_id?: number | string;
    readonly rows_read?: number;
    readonly rows_written?: number;
  };
}

export interface D1PreparedStatementLike {
  bind(...values: readonly unknown[]): D1PreparedStatementLike;
  first<T = unknown>(columnName?: string): Promise<T | null>;
  all<T = unknown>(): Promise<D1ResultLike<T>>;
  run<T = unknown>(): Promise<D1ResultLike<T>>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
  batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]>;
  exec(query: string): Promise<unknown>;
}

export interface HyperdriveBindingLike {
  readonly connectionString: string;
}

export type ConsoleD1StorageTarget = {
  readonly kind: 'd1';
  readonly bindingName: D1BindingName;
  readonly databaseName: D1DatabaseName;
  readonly database: D1DatabaseLike;
  readonly hyperdriveBindingName?: never;
  readonly hyperdrive?: never;
  readonly postgresSchema?: never;
};

export type ConsolePostgresStorageTarget = {
  readonly kind: 'postgres';
  readonly hyperdriveBindingName: HyperdriveBindingName;
  readonly hyperdrive: HyperdriveBindingLike;
  readonly postgresSchema: PostgresSchemaName;
  readonly bindingName?: never;
  readonly databaseName?: never;
  readonly database?: never;
};

export type SignerD1DoStorageTarget = {
  readonly kind: 'cloudflare_d1_do';
  readonly metadataBindingName: D1BindingName;
  readonly metadataDatabaseName: D1DatabaseName;
  readonly metadataDatabase: D1DatabaseLike;
  readonly thresholdStoreBindingName: DurableObjectBindingName;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
  readonly hyperdriveBindingName?: never;
  readonly hyperdrive?: never;
  readonly postgresSchema?: never;
};

export type SignerPostgresStorageTarget = {
  readonly kind: 'postgres';
  readonly hyperdriveBindingName: HyperdriveBindingName;
  readonly hyperdrive: HyperdriveBindingLike;
  readonly postgresSchema: PostgresSchemaName;
  readonly kekProvider: SigningRootKekProvider;
  readonly metadataBindingName?: never;
  readonly metadataDatabaseName?: never;
  readonly metadataDatabase?: never;
  readonly thresholdStoreBindingName?: never;
  readonly thresholdStore?: never;
};

export type ConsoleStorageTarget = ConsoleD1StorageTarget | ConsolePostgresStorageTarget;
export type SignerStorageTarget = SignerD1DoStorageTarget | SignerPostgresStorageTarget;

export type CloudflareTenantStorageRoute = {
  readonly kind: 'cloudflare_d1_do';
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
  readonly routeVersion: RouteVersion;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly console: ConsoleD1StorageTarget;
  readonly signer: SignerD1DoStorageTarget;
  readonly migrationReason?: never;
  readonly postgresRegion?: never;
  readonly postgresBackupRegion?: never;
};

export type PostgresTenantStorageRoute = {
  readonly kind: 'postgres';
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
  readonly routeVersion: RouteVersion;
  readonly migrationReason: PostgresMigrationReason;
  readonly postgresRegion: string;
  readonly postgresBackupRegion: string;
  readonly console: ConsolePostgresStorageTarget;
  readonly signer: SignerPostgresStorageTarget;
  readonly topology?: never;
  readonly jurisdiction?: never;
};

export type TenantStorageRoute = CloudflareTenantStorageRoute | PostgresTenantStorageRoute;

export type ResolveTenantStorageRouteInput = {
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
};

export interface TenantStorageRouteResolver {
  resolveTenantStorageRoute(input: ResolveTenantStorageRouteInput): TenantStorageRoute;
}

export interface StaticCloudflareTenantStorageRouteResolverInput {
  readonly routeVersion: RouteVersion;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly console: ConsoleD1StorageTarget;
  readonly signer: SignerD1DoStorageTarget;
}

export interface StaticCloudflareTenantStorageRouteResolverBindingInput {
  readonly routeVersion: RouteVersion;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly consoleBindingName: D1BindingName;
  readonly consoleDatabaseName: D1DatabaseName;
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerMetadataBindingName: D1BindingName;
  readonly signerMetadataDatabaseName: D1DatabaseName;
  readonly signerMetadataDatabase: D1DatabaseLike;
  readonly thresholdStoreBindingName: DurableObjectBindingName;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
}

export interface TenantStoreFactory<TStores> {
  createStores(route: TenantStorageRoute): TStores;
}

export type TenantStorageRouteDiagnostic = {
  readonly backendFamily: TenantStorageBackendFamily;
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
  readonly routeVersion: RouteVersion;
};

function assertNeverTenantStorageRoute(route: never): never {
  throw new Error(`Unhandled tenant storage route kind: ${JSON.stringify(route)}`);
}

function normalizeRequiredString(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${field} is required`);
  }
  return normalized;
}

function requireOrgId(value: OrgId): OrgId {
  normalizeRequiredString(value, 'orgId');
  return value;
}

function normalizeRouteVersion(value: RouteVersion): RouteVersion {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error('routeVersion must be a positive integer');
  }
  return value;
}

export function createConsoleD1StorageTarget(input: {
  readonly bindingName: D1BindingName;
  readonly databaseName: D1DatabaseName;
  readonly database: D1DatabaseLike;
}): ConsoleD1StorageTarget {
  return {
    kind: 'd1',
    bindingName: normalizeRequiredString(input.bindingName, 'console D1 bindingName'),
    databaseName: normalizeRequiredString(input.databaseName, 'console D1 databaseName'),
    database: input.database,
  };
}

export function createSignerD1DoStorageTarget(input: {
  readonly metadataBindingName: D1BindingName;
  readonly metadataDatabaseName: D1DatabaseName;
  readonly metadataDatabase: D1DatabaseLike;
  readonly thresholdStoreBindingName: DurableObjectBindingName;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
}): SignerD1DoStorageTarget {
  return {
    kind: 'cloudflare_d1_do',
    metadataBindingName: normalizeRequiredString(
      input.metadataBindingName,
      'signer D1 metadataBindingName',
    ),
    metadataDatabaseName: normalizeRequiredString(
      input.metadataDatabaseName,
      'signer D1 metadataDatabaseName',
    ),
    metadataDatabase: input.metadataDatabase,
    thresholdStoreBindingName: normalizeRequiredString(
      input.thresholdStoreBindingName,
      'signer thresholdStoreBindingName',
    ),
    thresholdStore: input.thresholdStore,
    kekProvider: input.kekProvider,
  };
}

export function createCloudflareTenantStorageRoute(input: {
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
  readonly routeVersion: RouteVersion;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly console: ConsoleD1StorageTarget;
  readonly signer: SignerD1DoStorageTarget;
}): CloudflareTenantStorageRoute {
  return {
    kind: 'cloudflare_d1_do',
    namespace: normalizeRequiredString(input.namespace, 'namespace'),
    orgId: requireOrgId(input.orgId),
    routeVersion: normalizeRouteVersion(input.routeVersion),
    topology: input.topology,
    jurisdiction: input.jurisdiction,
    console: input.console,
    signer: input.signer,
  };
}

export class StaticCloudflareTenantStorageRouteResolver implements TenantStorageRouteResolver {
  private readonly routeVersion: RouteVersion;
  private readonly topology: CloudflareTenantTopology;
  private readonly jurisdiction: TenantDataJurisdiction;
  private readonly consoleTarget: ConsoleD1StorageTarget;
  private readonly signerTarget: SignerD1DoStorageTarget;

  constructor(input: StaticCloudflareTenantStorageRouteResolverInput) {
    this.routeVersion = normalizeRouteVersion(input.routeVersion);
    this.topology = input.topology;
    this.jurisdiction = input.jurisdiction;
    this.consoleTarget = input.console;
    this.signerTarget = input.signer;
  }

  resolveTenantStorageRoute(input: ResolveTenantStorageRouteInput): CloudflareTenantStorageRoute {
    return createCloudflareTenantStorageRoute({
      namespace: input.namespace,
      orgId: input.orgId,
      routeVersion: this.routeVersion,
      topology: this.topology,
      jurisdiction: this.jurisdiction,
      console: this.consoleTarget,
      signer: this.signerTarget,
    });
  }
}

export function createStaticCloudflareTenantStorageRouteResolver(
  input: StaticCloudflareTenantStorageRouteResolverInput,
): StaticCloudflareTenantStorageRouteResolver {
  return new StaticCloudflareTenantStorageRouteResolver(input);
}

export function createStaticCloudflareTenantStorageRouteResolverFromBindings(
  input: StaticCloudflareTenantStorageRouteResolverBindingInput,
): StaticCloudflareTenantStorageRouteResolver {
  const consoleTarget = createConsoleD1StorageTarget({
    bindingName: input.consoleBindingName,
    databaseName: input.consoleDatabaseName,
    database: input.consoleDatabase,
  });
  const signerTarget = createSignerD1DoStorageTarget({
    metadataBindingName: input.signerMetadataBindingName,
    metadataDatabaseName: input.signerMetadataDatabaseName,
    metadataDatabase: input.signerMetadataDatabase,
    thresholdStoreBindingName: input.thresholdStoreBindingName,
    thresholdStore: input.thresholdStore,
    kekProvider: input.kekProvider,
  });
  return createStaticCloudflareTenantStorageRouteResolver({
    routeVersion: input.routeVersion,
    topology: input.topology,
    jurisdiction: input.jurisdiction,
    console: consoleTarget,
    signer: signerTarget,
  });
}

export function tenantStorageRouteBackendFamily(
  route: TenantStorageRoute,
): TenantStorageBackendFamily {
  switch (route.kind) {
    case 'cloudflare_d1_do':
      return 'cloudflare_d1_do';
    case 'postgres':
      return 'postgres';
    default:
      return assertNeverTenantStorageRoute(route);
  }
}

export function tenantStorageRouteDiagnostic(
  route: TenantStorageRoute,
): TenantStorageRouteDiagnostic {
  return {
    backendFamily: tenantStorageRouteBackendFamily(route),
    namespace: route.namespace,
    orgId: route.orgId,
    routeVersion: route.routeVersion,
  };
}

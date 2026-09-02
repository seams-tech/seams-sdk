import {
  createCloudflareTenantStorageRoute as createSignerCloudflareTenantStorageRoute,
  createSignerD1DoStorageTarget,
  type CloudflareTenantStorageRoute as CloudflareSignerTenantStorageRoute,
  type CloudflareTenantTopology,
  type D1BindingName,
  type D1DatabaseLike,
  type D1DatabaseName,
  type HyperdriveBindingLike,
  type HyperdriveBindingName,
  type NamespaceId,
  type OrgId,
  type PostgresSchemaName,
  type PostgresTenantStorageRoute as PostgresSignerTenantStorageRoute,
  type ResolveTenantStorageRouteInput,
  type RouteVersion,
  type SignerD1DoStorageTarget,
  type TenantDataJurisdiction,
  type TenantStorageRouteDiagnostic,
} from '@seams/wallet-server/cloud-host';

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

export type CloudflareTenantStorageRoute = CloudflareSignerTenantStorageRoute & {
  readonly console: ConsoleD1StorageTarget;
};

export type PostgresTenantStorageRoute = PostgresSignerTenantStorageRoute & {
  readonly console: ConsolePostgresStorageTarget;
};

export type TenantStorageRoute = CloudflareTenantStorageRoute | PostgresTenantStorageRoute;

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
}

function normalizeRequiredString(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`${field} is required`);
  }
  return normalized;
}

function backendFamily(route: TenantStorageRoute): TenantStorageRouteDiagnostic['backendFamily'] {
  switch (route.kind) {
    case 'cloudflare_d1_do':
      return 'cloudflare_d1_do';
    case 'postgres':
      return 'postgres';
  }
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

export function createCloudflareTenantStorageRoute(input: {
  readonly namespace: NamespaceId;
  readonly orgId: OrgId;
  readonly routeVersion: RouteVersion;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly console: ConsoleD1StorageTarget;
  readonly signer: SignerD1DoStorageTarget;
}): CloudflareTenantStorageRoute {
  const signerRoute = createSignerCloudflareTenantStorageRoute({
    namespace: input.namespace,
    orgId: input.orgId,
    routeVersion: input.routeVersion,
    topology: input.topology,
    jurisdiction: input.jurisdiction,
    signer: input.signer,
  });
  return {
    kind: signerRoute.kind,
    namespace: signerRoute.namespace,
    orgId: signerRoute.orgId,
    routeVersion: signerRoute.routeVersion,
    topology: signerRoute.topology,
    jurisdiction: signerRoute.jurisdiction,
    console: input.console,
    signer: signerRoute.signer,
  };
}

export class StaticCloudflareTenantStorageRouteResolver implements TenantStorageRouteResolver {
  private readonly input: StaticCloudflareTenantStorageRouteResolverInput;

  constructor(input: StaticCloudflareTenantStorageRouteResolverInput) {
    this.input = input;
  }

  resolveTenantStorageRoute(input: ResolveTenantStorageRouteInput): CloudflareTenantStorageRoute {
    return createCloudflareTenantStorageRoute({
      namespace: input.namespace,
      orgId: input.orgId,
      routeVersion: this.input.routeVersion,
      topology: this.input.topology,
      jurisdiction: this.input.jurisdiction,
      console: this.input.console,
      signer: this.input.signer,
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
  });
  return createStaticCloudflareTenantStorageRouteResolver({
    routeVersion: input.routeVersion,
    topology: input.topology,
    jurisdiction: input.jurisdiction,
    console: consoleTarget,
    signer: signerTarget,
  });
}

export function tenantStorageRouteDiagnostic(
  route: TenantStorageRoute,
): TenantStorageRouteDiagnostic {
  return {
    backendFamily: backendFamily(route),
    namespace: route.namespace,
    orgId: route.orgId,
    routeVersion: route.routeVersion,
  };
}

import type {
  CloudflareTenantStorageRoute,
  D1DatabaseLike,
  D1PreparedStatementLike,
  HyperdriveBindingLike,
  PostgresTenantStorageRoute,
  SignerD1DoStorageTarget,
  SignerPostgresStorageTarget,
  TenantStorageRoute,
  TenantStorageRouteResolver,
} from './tenantRoute';
import {
  createCloudflareTenantStorageRoute,
  createStaticCloudflareTenantStorageRouteResolver,
  createStaticCloudflareTenantStorageRouteResolverFromBindings,
} from './tenantRoute';
import { parseOrgId, type OrgId } from '@shared/utils/domainIds';

function orgIdFromString(input: string): OrgId {
  const parsed = parseOrgId(input);
  if (!parsed.ok) {
    throw new Error(`invalid test org id ${input}`);
  }
  return parsed.value;
}

const preparedStatement: D1PreparedStatementLike = {
  bind(): D1PreparedStatementLike {
    return preparedStatement;
  },
  async first<T = unknown>(): Promise<T | null> {
    return null;
  },
  async all<T = unknown>(): Promise<{
    readonly results?: readonly T[];
    readonly success: boolean;
  }> {
    return { results: [], success: true };
  },
  async run<T = unknown>(): Promise<{
    readonly results?: readonly T[];
    readonly success: boolean;
  }> {
    return { results: [], success: true };
  },
};

const d1Database: D1DatabaseLike = {
  prepare(): D1PreparedStatementLike {
    return preparedStatement;
  },
  async batch<T = unknown>(): Promise<readonly T[]> {
    return [];
  },
  async exec(): Promise<unknown> {
    return null;
  },
};

const signerD1DoTarget: SignerD1DoStorageTarget = {
  kind: 'cloudflare_d1_do',
  metadataBindingName: 'SIGNER_DB',
  metadataDatabaseName: 'seams-signer',
  metadataDatabase: d1Database,
};

const hyperdrive: HyperdriveBindingLike = {
  connectionString: 'postgres://example.invalid/seams',
};

const signerPostgresTarget: SignerPostgresStorageTarget = {
  kind: 'postgres',
  hyperdriveBindingName: 'SEAMS_POSTGRES',
  hyperdrive,
  postgresSchema: 'seams_signer',
};

const orgId = orgIdFromString('org_test');

const cloudflareRoute: CloudflareTenantStorageRoute = createCloudflareTenantStorageRoute({
  namespace: 'seams',
  orgId,
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  signer: signerD1DoTarget,
});

const postgresRoute: PostgresTenantStorageRoute = {
  kind: 'postgres',
  namespace: 'seams',
  orgId,
  routeVersion: 2,
  migrationReason: 'd1_size_limit',
  postgresRegion: 'wnam',
  postgresBackupRegion: 'enam',
  signer: signerPostgresTarget,
};

const resolver = createStaticCloudflareTenantStorageRouteResolver({
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  signer: signerD1DoTarget,
});
const resolvedRoute = resolver.resolveTenantStorageRoute({
  namespace: 'seams',
  orgId,
});
const resolvedRouteKind: 'cloudflare_d1_do' = resolvedRoute.kind;

const resolverFromBindings = createStaticCloudflareTenantStorageRouteResolverFromBindings({
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  signerMetadataBindingName: 'SIGNER_DB',
  signerMetadataDatabaseName: 'seams-signer',
  signerMetadataDatabase: d1Database,
});
const resolvedFromBindings = resolverFromBindings.resolveTenantStorageRoute({
  namespace: 'seams',
  orgId,
});
const resolvedFromBindingsKind: 'cloudflare_d1_do' = resolvedFromBindings.kind;

const postgresResolver: TenantStorageRouteResolver = {
  resolveTenantStorageRoute(): TenantStorageRoute {
    return postgresRoute;
  },
};
const resolvedPostgresRoute = postgresResolver.resolveTenantStorageRoute({
  namespace: 'seams',
  orgId,
});
const resolvedPostgresRouteKind: 'postgres' =
  resolvedPostgresRoute.kind === 'postgres' ? resolvedPostgresRoute.kind : postgresRoute.kind;

const legacyConsoleTarget = {
  kind: 'd1',
  bindingName: 'CONSOLE_DB',
  databaseName: 'seams-console',
  database: d1Database,
} as const;

const invalidCloudflareConsoleTarget: CloudflareTenantStorageRoute = {
  ...cloudflareRoute,
  // @ts-expect-error Public tenant routes cannot carry console storage.
  console: legacyConsoleTarget,
};

const cloudflareRouteHasNoConsoleKeys: Record<
  Extract<'console', keyof CloudflareTenantStorageRoute>,
  never
> = {};
const postgresRouteHasNoConsoleKeys: Record<
  Extract<'console', keyof PostgresTenantStorageRoute>,
  never
> = {};

const invalidCloudflareSignerTarget: CloudflareTenantStorageRoute = {
  kind: 'cloudflare_d1_do',
  namespace: 'seams',
  orgId,
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  // @ts-expect-error Cloudflare routes require a D1/DO signer target.
  signer: signerPostgresTarget,
};

const invalidCloudflareMigrationReason: CloudflareTenantStorageRoute = {
  ...cloudflareRoute,
  // @ts-expect-error Cloudflare routes cannot carry a Postgres migration reason.
  migrationReason: 'd1_size_limit',
};

const invalidPostgresConsoleTarget: PostgresTenantStorageRoute = {
  ...postgresRoute,
  // @ts-expect-error Public tenant routes cannot carry console storage.
  console: {
    kind: 'postgres',
    hyperdriveBindingName: 'SEAMS_POSTGRES',
    hyperdrive,
    postgresSchema: 'seams_console',
  },
};

const invalidPostgresSignerTarget: PostgresTenantStorageRoute = {
  kind: 'postgres',
  namespace: 'seams',
  orgId,
  routeVersion: 2,
  migrationReason: 'd1_size_limit',
  postgresRegion: 'wnam',
  postgresBackupRegion: 'enam',
  // @ts-expect-error Postgres routes require a Postgres signer target.
  signer: signerD1DoTarget,
};

const invalidPostgresTopology: PostgresTenantStorageRoute = {
  ...postgresRoute,
  // @ts-expect-error Postgres routes cannot carry a Cloudflare topology.
  topology: 'shared',
};

void cloudflareRoute;
void postgresRoute;
void resolvedRouteKind;
void resolvedFromBindingsKind;
void resolvedPostgresRouteKind;
void invalidCloudflareConsoleTarget;
void cloudflareRouteHasNoConsoleKeys;
void postgresRouteHasNoConsoleKeys;
void invalidCloudflareSignerTarget;
void invalidCloudflareMigrationReason;
void invalidPostgresConsoleTarget;
void invalidPostgresSignerTarget;
void invalidPostgresTopology;

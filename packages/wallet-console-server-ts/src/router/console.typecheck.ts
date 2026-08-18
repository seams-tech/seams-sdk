import type { ConsoleRouterOptions } from './console';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  ResolveTenantStorageRouteInput,
} from '@seams/wallet-server/cloud-host';
import type {
  CloudflareTenantStorageRoute,
  TenantStorageRouteResolver,
} from './cloudflare/tenantStorageRoute';
import { parseOrgId, type OrgId } from '@seams/wallet-server/cloud-host';

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

const database: D1DatabaseLike = {
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

function orgIdFromString(input: string): OrgId {
  const parsed = parseOrgId(input);
  if (!parsed.ok) {
    throw new Error(`invalid test org id ${input}`);
  }
  return parsed.value;
}

const route: CloudflareTenantStorageRoute = {
  kind: 'cloudflare_d1_do',
  namespace: 'seams',
  orgId: orgIdFromString('org_test'),
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  console: {
    kind: 'd1',
    bindingName: 'CONSOLE_DB',
    databaseName: 'seams-console',
    database,
  },
  signer: {
    kind: 'cloudflare_d1_do',
    metadataBindingName: 'SIGNER_DB',
    metadataDatabaseName: 'seams-signer',
    metadataDatabase: database,
  },
};

const resolver: TenantStorageRouteResolver = {
  resolveTenantStorageRoute(_input: ResolveTenantStorageRouteInput): CloudflareTenantStorageRoute {
    return route;
  },
};

const routedOptions: ConsoleRouterOptions = {
  tenantStorageRouteResolver: resolver,
  tenantStorageNamespace: 'seams',
};

const unroutedOptions: ConsoleRouterOptions = {};

// @ts-expect-error Tenant storage namespace is invalid without a route resolver.
const namespaceWithoutResolver: ConsoleRouterOptions = {
  tenantStorageNamespace: 'seams',
};

// @ts-expect-error Tenant storage route resolver requires a namespace.
const resolverWithoutNamespace: ConsoleRouterOptions = {
  tenantStorageRouteResolver: resolver,
};

void routedOptions;
void unroutedOptions;
void namespaceWithoutResolver;
void resolverWithoutNamespace;

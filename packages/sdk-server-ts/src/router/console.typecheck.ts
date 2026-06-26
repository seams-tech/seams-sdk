import type { ConsoleRouterOptions } from './console';
import type {
  CloudflareTenantStorageRoute,
  D1DatabaseLike,
  D1PreparedStatementLike,
  ResolveTenantStorageRouteInput,
  TenantStorageRouteResolver,
} from '../storage/tenantRoute';
import type { CloudflareDurableObjectNamespaceLike } from '../core/types';
import type { SigningRootKekProvider } from '../core/ThresholdService/signingRootKekProvider';

const preparedStatement: D1PreparedStatementLike = {
  bind(): D1PreparedStatementLike {
    return preparedStatement;
  },
  async first<T = unknown>(): Promise<T | null> {
    return null;
  },
  async all<T = unknown>(): Promise<{ readonly results?: readonly T[]; readonly success: boolean }> {
    return { results: [], success: true };
  },
  async run<T = unknown>(): Promise<{ readonly results?: readonly T[]; readonly success: boolean }> {
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

const thresholdStore: CloudflareDurableObjectNamespaceLike = {
  idFromName(name: string): unknown {
    return name;
  },
  get() {
    return {
      async fetch(): Promise<Response> {
        return new Response('{}');
      },
    };
  },
};

const kekProvider: SigningRootKekProvider = {
  kind: 'worker_secret',
  workerSecretsByKekId: { 'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
  encoding: 'base64url',
};

const route: CloudflareTenantStorageRoute = {
  kind: 'cloudflare',
  namespace: 'seams',
  orgId: 'org_test',
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
    thresholdStoreBindingName: 'THRESHOLD_STORE',
    thresholdStore,
    kekProvider,
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

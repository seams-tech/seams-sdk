import type { ConsoleRouterOptions } from '@seams-internal/wallet-console-server/router/console';
import type { RouterApiOptions } from '@seams/sdk-server/cloud-host';
import type { D1DatabaseLike, D1PreparedStatementLike } from '@seams/sdk-server/cloud-host';
import { parseOrgId, type OrgId } from '@seams/sdk-server/cloud-host';
import {
  createStaticCloudflareTenantStorageRouteResolverFromBindings,
} from './tenantStorageRoute';
import type {
  CloudflareD1ConsoleRouterStorageOptions,
  CloudflareD1RouterApiStorageOptions,
  CloudflareD1ConsoleOnlyServiceBundleOptions,
  CloudflareD1ConsoleServiceBundle,
  CloudflareD1ConsoleServiceBundleOptions,
} from './d1ConsoleServices';
import {
  asConsoleRouterOptions,
  asRouterApiOptions,
  createCloudflareD1ConsoleOnlyServiceBundle,
} from './d1ConsoleServices';

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

const bundleOptions: CloudflareD1ConsoleServiceBundleOptions = {
  bindings: {
    consoleDatabase: database,
    signerMetadataDatabase: database,
  },
  route: {
    namespace: 'seams',
  },
};

const consoleOnlyBundleOptions: CloudflareD1ConsoleOnlyServiceBundleOptions = {
  bindings: {
    consoleDatabase: database,
  },
  route: {
    namespace: 'seams',
  },
};

const invalidConsoleOnlySignerDatabase: CloudflareD1ConsoleOnlyServiceBundleOptions = {
  bindings: {
    consoleDatabase: database,
    // @ts-expect-error Console-only staging bundles cannot receive signer metadata D1.
    signerMetadataDatabase: database,
  },
  route: {
    namespace: 'seams',
  },
};

const routeResolver = createStaticCloudflareTenantStorageRouteResolverFromBindings({
  routeVersion: 1,
  topology: 'shared',
  jurisdiction: 'automatic',
  consoleBindingName: 'CONSOLE_DB',
  consoleDatabaseName: 'seams-console',
  consoleDatabase: database,
  signerMetadataBindingName: 'SIGNER_DB',
  signerMetadataDatabaseName: 'seams-signer',
  signerMetadataDatabase: database,
});

const cloudflareRoute = routeResolver.resolveTenantStorageRoute({
  namespace: 'seams',
  orgId: orgIdFromString('org_1'),
});

const missingSignerBindings: CloudflareD1ConsoleServiceBundleOptions = {
  // @ts-expect-error D1 console bundle requires signer metadata.
  bindings: {
    consoleDatabase: database,
  },
  route: {
    namespace: 'seams',
  },
};

const missingNamespace: CloudflareD1ConsoleServiceBundleOptions = {
  bindings: {
    consoleDatabase: database,
    signerMetadataDatabase: database,
  },
  // @ts-expect-error Route namespace is required at the bundle boundary.
  route: {},
};

declare const routerStorageOptions: CloudflareD1ConsoleRouterStorageOptions;
declare const relayStorageOptions: CloudflareD1RouterApiStorageOptions;
declare const serviceBundle: CloudflareD1ConsoleServiceBundle;

const consoleOptions: ConsoleRouterOptions = {
  ...asConsoleRouterOptions(routerStorageOptions),
  healthz: true,
};

const relayOptions: RouterApiOptions = {
  ...asRouterApiOptions(relayStorageOptions),
  healthz: true,
};

const relayOptionsFromBundle: RouterApiOptions = {
  ...asRouterApiOptions(serviceBundle.routerApiRouterOptions),
};

const consoleOnlyBundle = createCloudflareD1ConsoleOnlyServiceBundle(consoleOnlyBundleOptions);

void bundleOptions;
void consoleOnlyBundleOptions;
void invalidConsoleOnlySignerDatabase;
void cloudflareRoute;
void missingSignerBindings;
void missingNamespace;
void consoleOptions;
void relayOptions;
void relayOptionsFromBundle;
void consoleOnlyBundle;

import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { SigningRootKekProvider } from '../../core/ThresholdService/signingRootKekProvider';
import type { ConsoleRouterOptions } from '../console';
import type { RelayRouterOptions } from '../relay';
import {
  createStaticCloudflareTenantStorageRouteResolverFromBindings,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
  type PostgresTenantStorageRoute,
} from '../../storage/tenantRoute';
import type {
  CloudflareD1ConsoleRouterStorageOptions,
  CloudflareD1RelayRouterStorageOptions,
  CloudflareD1ConsoleServiceBundle,
  CloudflareD1ConsoleServiceBundleOptions,
  CloudflareD1SigningRootSecretAdapterOptions,
} from './d1ConsoleServices';
import {
  asConsoleRouterOptions,
  asRelayRouterOptions,
  createCloudflareD1SigningRootSecretAdapters,
} from './d1ConsoleServices';

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

const bundleOptions: CloudflareD1ConsoleServiceBundleOptions = {
  bindings: {
    consoleDatabase: database,
    signerMetadataDatabase: database,
    thresholdStore,
    kekProvider,
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
  thresholdStoreBindingName: 'THRESHOLD_STORE',
  thresholdStore,
  kekProvider,
});

const cloudflareRoute = routeResolver.resolveTenantStorageRoute({
  namespace: 'seams',
  orgId: 'org_1',
});

const signerSecretOptions: CloudflareD1SigningRootSecretAdapterOptions = {
  route: cloudflareRoute,
  projectId: 'project_1',
  envId: 'env_1',
  envelopeVersion: 'aes-256-gcm-v1',
  lastAuditEventId: 'audit_1',
  policy: {
    protocol: 'threshold-prf',
    threshold: 2,
    shareCount: 3,
  },
};

const signerSecretAdapters = createCloudflareD1SigningRootSecretAdapters(signerSecretOptions);

declare const postgresRoute: PostgresTenantStorageRoute;

const invalidPostgresSignerSecretOptions: CloudflareD1SigningRootSecretAdapterOptions = {
  // @ts-expect-error D1 signer secret adapters require a Cloudflare D1/DO route.
  route: postgresRoute,
  projectId: 'project_1',
  envId: 'env_1',
  envelopeVersion: 'aes-256-gcm-v1',
  lastAuditEventId: 'audit_1',
  policy: {
    protocol: 'threshold-prf',
    threshold: 2,
    shareCount: 3,
  },
};

// @ts-expect-error D1 signer secret adapters require env identity.
const missingSignerSecretEnvId: CloudflareD1SigningRootSecretAdapterOptions = {
  route: cloudflareRoute,
  projectId: 'project_1',
  envelopeVersion: 'aes-256-gcm-v1',
  lastAuditEventId: 'audit_1',
  policy: {
    protocol: 'threshold-prf',
    threshold: 2,
    shareCount: 3,
  },
};

const missingSignerBindings: CloudflareD1ConsoleServiceBundleOptions = {
  // @ts-expect-error D1 console bundle requires signer metadata and DO bindings.
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
    thresholdStore,
    kekProvider,
  },
  // @ts-expect-error Route namespace is required at the bundle boundary.
  route: {},
};

declare const routerStorageOptions: CloudflareD1ConsoleRouterStorageOptions;
declare const relayStorageOptions: CloudflareD1RelayRouterStorageOptions;
declare const serviceBundle: CloudflareD1ConsoleServiceBundle;

const consoleOptions: ConsoleRouterOptions = {
  ...asConsoleRouterOptions(routerStorageOptions),
  healthz: true,
};

const relayOptions: RelayRouterOptions = {
  ...asRelayRouterOptions(relayStorageOptions),
  healthz: true,
};

const relayOptionsFromBundle: RelayRouterOptions = {
  ...asRelayRouterOptions(serviceBundle.relayRouterOptions),
};

void bundleOptions;
void signerSecretAdapters;
void invalidPostgresSignerSecretOptions;
void missingSignerSecretEnvId;
void missingSignerBindings;
void missingNamespace;
void consoleOptions;
void relayOptions;
void relayOptionsFromBundle;

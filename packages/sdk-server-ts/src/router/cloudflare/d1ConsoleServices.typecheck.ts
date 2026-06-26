import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { SigningRootKekProvider } from '../../core/ThresholdService/signingRootKekProvider';
import type { ConsoleRouterOptions } from '../console';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import type {
  CloudflareD1ConsoleRouterStorageOptions,
  CloudflareD1ConsoleServiceBundleOptions,
} from './d1ConsoleServices';
import { asConsoleRouterOptions } from './d1ConsoleServices';

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

const consoleOptions: ConsoleRouterOptions = {
  ...asConsoleRouterOptions(routerStorageOptions),
  healthz: true,
};

void bundleOptions;
void missingSignerBindings;
void missingNamespace;
void consoleOptions;

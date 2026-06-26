import type { D1DatabaseLike, D1PreparedStatementLike } from '../storage/tenantRoute';
import type { D1WalletAuthMethodStoreOptions } from './WalletAuthMethodStore';
import type { D1WalletStoreOptions } from './WalletStore';

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

const validWalletStoreOptions: D1WalletStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validAuthMethodStoreOptions: D1WalletAuthMethodStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

// @ts-expect-error D1 wallet metadata storage requires org identity.
const missingWalletOrgId: D1WalletStoreOptions = {
  database,
  namespace: 'seams',
  projectId: 'project_1',
  envId: 'env_1',
};

// @ts-expect-error D1 wallet auth-method storage requires environment identity.
const missingAuthMethodEnvId: D1WalletAuthMethodStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
};

void validWalletStoreOptions;
void validAuthMethodStoreOptions;
void missingWalletOrgId;
void missingAuthMethodEnvId;

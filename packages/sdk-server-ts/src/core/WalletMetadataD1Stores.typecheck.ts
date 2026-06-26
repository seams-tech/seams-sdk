import type { D1DatabaseLike, D1PreparedStatementLike } from '../storage/tenantRoute';
import type { D1RecoveryExecutionStoreOptions } from './RecoveryExecutionStore';
import type { D1RecoverySessionStoreOptions } from './RecoverySessionStore';
import type { D1WebAuthnAuthenticatorStoreOptions } from './WebAuthnAuthenticatorStore';
import type { D1WebAuthnCredentialBindingStoreOptions } from './WebAuthnCredentialBindingStore';
import type { D1WebAuthnLoginChallengeStoreOptions } from './WebAuthnLoginChallengeStore';
import type { D1WebAuthnSyncChallengeStoreOptions } from './WebAuthnSyncChallengeStore';
import type { D1IdentityStoreOptions } from './IdentityStore';
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

const validWebAuthnAuthenticatorOptions: D1WebAuthnAuthenticatorStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validWebAuthnCredentialOptions: D1WebAuthnCredentialBindingStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validWebAuthnLoginChallengeOptions: D1WebAuthnLoginChallengeStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validWebAuthnSyncChallengeOptions: D1WebAuthnSyncChallengeStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validIdentityStoreOptions: D1IdentityStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validRecoverySessionStoreOptions: D1RecoverySessionStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
};

const validRecoveryExecutionStoreOptions: D1RecoveryExecutionStoreOptions = {
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

// @ts-expect-error D1 WebAuthn authenticator storage requires project identity.
const missingWebAuthnProjectId: D1WebAuthnAuthenticatorStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  envId: 'env_1',
};

// @ts-expect-error D1 WebAuthn credential storage requires environment identity.
const missingWebAuthnCredentialEnvId: D1WebAuthnCredentialBindingStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
};

// @ts-expect-error D1 WebAuthn challenge storage requires org identity.
const missingWebAuthnChallengeOrgId: D1WebAuthnLoginChallengeStoreOptions = {
  database,
  namespace: 'seams',
  projectId: 'project_1',
  envId: 'env_1',
};

// @ts-expect-error D1 identity storage requires project identity.
const missingIdentityProjectId: D1IdentityStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  envId: 'env_1',
};

// @ts-expect-error D1 recovery-session storage requires environment identity.
const missingRecoverySessionEnvId: D1RecoverySessionStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
};

// @ts-expect-error D1 recovery-execution storage requires org identity.
const missingRecoveryExecutionOrgId: D1RecoveryExecutionStoreOptions = {
  database,
  namespace: 'seams',
  projectId: 'project_1',
  envId: 'env_1',
};

void validWalletStoreOptions;
void validAuthMethodStoreOptions;
void validWebAuthnAuthenticatorOptions;
void validWebAuthnCredentialOptions;
void validWebAuthnLoginChallengeOptions;
void validWebAuthnSyncChallengeOptions;
void validIdentityStoreOptions;
void validRecoverySessionStoreOptions;
void validRecoveryExecutionStoreOptions;
void missingWalletOrgId;
void missingAuthMethodEnvId;
void missingWebAuthnProjectId;
void missingWebAuthnCredentialEnvId;
void missingWebAuthnChallengeOrgId;
void missingIdentityProjectId;
void missingRecoverySessionEnvId;
void missingRecoveryExecutionOrgId;

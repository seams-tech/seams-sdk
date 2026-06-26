import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../storage/tenantRoute';
import type { D1SigningRootSecretStoreOptions } from './SigningRootSecretStore';

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

const validOptions: D1SigningRootSecretStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
  envelopeVersion: 'aes-256-gcm-v1',
  lastAuditEventId: 'audit_1',
};

// @ts-expect-error D1 signer secret storage requires org identity.
const missingOrgId: D1SigningRootSecretStoreOptions = {
  database,
  namespace: 'seams',
  projectId: 'project_1',
  envId: 'env_1',
  envelopeVersion: 'aes-256-gcm-v1',
  lastAuditEventId: 'audit_1',
};

// @ts-expect-error D1 signer secret storage requires envelope version metadata.
const missingEnvelopeVersion: D1SigningRootSecretStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
  lastAuditEventId: 'audit_1',
};

// @ts-expect-error D1 signer secret storage requires an audit marker.
const missingAuditEvent: D1SigningRootSecretStoreOptions = {
  database,
  namespace: 'seams',
  orgId: 'org_1',
  projectId: 'project_1',
  envId: 'env_1',
  envelopeVersion: 'aes-256-gcm-v1',
};

void validOptions;
void missingOrgId;
void missingEnvelopeVersion;
void missingAuditEvent;

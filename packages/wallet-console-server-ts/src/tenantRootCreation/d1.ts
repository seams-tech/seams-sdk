import {
  d1ChangedRows,
  queryD1One,
  type D1DatabaseLike,
  type D1Row,
} from '@seams/wallet-server/cloud-host';
import {
  TenantRootCreationGrantStoreError,
  type TenantRootCreationGrantServiceV1,
} from './service';
import type {
  TenantRootActiveLineageLookupV1,
  TenantRootCreationGrantIssueV1,
  TenantRootCreationGrantReadyInputV1,
  TenantRootCreationGrantReadyV1,
  TenantRootCreationGrantRecordV1,
  TenantRootIdentityV1,
} from './types';

export interface D1TenantRootCreationGrantServiceOptionsV1 {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now?: () => Date;
}

function requiredText(value: unknown, label: string): string {
  const text = String(value ?? '').trim();
  if (!text || text !== value) {
    throw new TenantRootCreationGrantStoreError('invalid_input', `${label} is invalid`);
  }
  return text;
}

function positiveSafeInteger(value: unknown, label: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new TenantRootCreationGrantStoreError('invalid_input', `${label} is invalid`);
  }
  return parsed;
}

function normalizeIdentity(identity: TenantRootIdentityV1): TenantRootIdentityV1 {
  return {
    orgId: requiredText(identity.orgId, 'identity.orgId'),
    projectId: requiredText(identity.projectId, 'identity.projectId'),
    envId: requiredText(identity.envId, 'identity.envId'),
    signingRootId: requiredText(identity.signingRootId, 'identity.signingRootId'),
    signingRootVersion: requiredText(identity.signingRootVersion, 'identity.signingRootVersion'),
  };
}

function normalizeIssue(input: TenantRootCreationGrantIssueV1): TenantRootCreationGrantIssueV1 {
  const issuedAtMs = positiveSafeInteger(input.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = positiveSafeInteger(input.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) {
    throw new TenantRootCreationGrantStoreError(
      'invalid_input',
      'expiresAtMs must follow issuedAtMs',
    );
  }
  return {
    operationId: requiredText(input.operationId, 'operationId'),
    identity: normalizeIdentity(input.identity),
    identityDigestB64u: requiredText(input.identityDigestB64u, 'identityDigestB64u'),
    custodyLineageB64u: requiredText(input.custodyLineageB64u, 'custodyLineageB64u'),
    grantNonceB64u: requiredText(input.grantNonceB64u, 'grantNonceB64u'),
    grantKeyId: requiredText(input.grantKeyId, 'grantKeyId'),
    grantB64u: requiredText(input.grantB64u, 'grantB64u'),
    grantDigestB64u: requiredText(input.grantDigestB64u, 'grantDigestB64u'),
    issuedAtMs,
    expiresAtMs,
  };
}

function parseReady(row: D1Row): TenantRootCreationGrantReadyV1 {
  return {
    revision: positiveSafeInteger(row.active_revision, 'active_revision'),
    rootCommitmentB64u: requiredText(row.root_commitment_b64u, 'root_commitment_b64u'),
    journalDigestB64u: requiredText(row.journal_digest_b64u, 'journal_digest_b64u'),
    capabilityDigestB64u: requiredText(row.capability_digest_b64u, 'capability_digest_b64u'),
  };
}

function parseRecord(row: D1Row): TenantRootCreationGrantRecordV1 {
  const base = {
    namespace: requiredText(row.namespace, 'namespace'),
    operationId: requiredText(row.operation_id, 'operation_id'),
    identity: {
      orgId: requiredText(row.org_id, 'org_id'),
      projectId: requiredText(row.project_id, 'project_id'),
      envId: requiredText(row.env_id, 'env_id'),
      signingRootId: requiredText(row.signing_root_id, 'signing_root_id'),
      signingRootVersion: requiredText(row.signing_root_version, 'signing_root_version'),
    },
    identityDigestB64u: requiredText(row.identity_digest_b64u, 'identity_digest_b64u'),
    custodyLineageB64u: requiredText(row.custody_lineage_b64u, 'custody_lineage_b64u'),
    grantNonceB64u: requiredText(row.grant_nonce_b64u, 'grant_nonce_b64u'),
    grantKeyId: requiredText(row.grant_key_id, 'grant_key_id'),
    grantB64u: requiredText(row.grant_b64u, 'grant_b64u'),
    grantDigestB64u: requiredText(row.grant_digest_b64u, 'grant_digest_b64u'),
    issuedAtMs: positiveSafeInteger(row.issued_at_ms, 'issued_at_ms'),
    expiresAtMs: positiveSafeInteger(row.expires_at_ms, 'expires_at_ms'),
    createdAtMs: positiveSafeInteger(row.created_at_ms, 'created_at_ms'),
    updatedAtMs: positiveSafeInteger(row.updated_at_ms, 'updated_at_ms'),
  };
  switch (row.status) {
    case 'ISSUED':
      return { ...base, status: 'ISSUED', ready: null };
    case 'ACTIVE':
      return { ...base, status: 'ACTIVE', ready: parseReady(row) };
    default:
      throw new TenantRootCreationGrantStoreError(
        'invalid_record',
        'tenant-root creation grant row has an invalid status',
      );
  }
}

function sameIdentity(left: TenantRootIdentityV1, right: TenantRootIdentityV1): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function sameOperationScope(
  record: TenantRootCreationGrantRecordV1,
  issue: TenantRootCreationGrantIssueV1,
): boolean {
  return (
    record.operationId === issue.operationId &&
    sameIdentity(record.identity, issue.identity) &&
    record.identityDigestB64u === issue.identityDigestB64u
  );
}

function sameReady(left: TenantRootCreationGrantReadyV1, right: TenantRootCreationGrantReadyV1) {
  return (
    left.revision === right.revision &&
    left.rootCommitmentB64u === right.rootCommitmentB64u &&
    left.journalDigestB64u === right.journalDigestB64u &&
    left.capabilityDigestB64u === right.capabilityDigestB64u
  );
}

async function readByOperation(
  database: D1DatabaseLike,
  namespace: string,
  operationId: string,
): Promise<TenantRootCreationGrantRecordV1 | null> {
  const row = await queryD1One(
    database,
    `SELECT * FROM tenant_root_creation_grants
     WHERE namespace = ?1 AND operation_id = ?2`,
    [namespace, operationId],
  );
  return row ? parseRecord(row) : null;
}

export function createD1TenantRootCreationGrantServiceV1(
  options: D1TenantRootCreationGrantServiceOptionsV1,
): TenantRootCreationGrantServiceV1 {
  const database = options.database;
  const namespace = requiredText(options.namespace, 'namespace');
  const now = options.now ?? (() => new Date());

  return {
    async findGrantByOperationId(operationId) {
      return await readByOperation(database, namespace, requiredText(operationId, 'operationId'));
    },

    async putOrGetGrant(rawInput) {
      const input = normalizeIssue(rawInput);
      const existingOperation = await readByOperation(database, namespace, input.operationId);
      if (existingOperation) {
        if (!sameOperationScope(existingOperation, input)) {
          throw new TenantRootCreationGrantStoreError(
            'grant_operation_conflict',
            'tenant-root creation operation already names a different grant',
          );
        }
        return existingOperation;
      }

      const existingIdentity = await queryD1One(
        database,
        `SELECT operation_id FROM tenant_root_creation_grants
         WHERE namespace = ?1 AND identity_digest_b64u = ?2`,
        [namespace, input.identityDigestB64u],
      );
      if (existingIdentity) {
        throw new TenantRootCreationGrantStoreError(
          'identity_lineage_exists',
          'tenant-root identity already has an initial custody lineage',
        );
      }

      const timestamp = positiveSafeInteger(now().getTime(), 'current time');
      await database
        .prepare(
          `INSERT OR IGNORE INTO tenant_root_creation_grants (
             namespace, operation_id, org_id, project_id, env_id,
             signing_root_id, signing_root_version, identity_digest_b64u,
             custody_lineage_b64u, grant_nonce_b64u, grant_key_id, grant_b64u,
             grant_digest_b64u, issued_at_ms, expires_at_ms, status,
             created_at_ms, updated_at_ms
           ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
             ?14, ?15, 'ISSUED', ?16, ?16
           )`,
        )
        .bind(
          namespace,
          input.operationId,
          input.identity.orgId,
          input.identity.projectId,
          input.identity.envId,
          input.identity.signingRootId,
          input.identity.signingRootVersion,
          input.identityDigestB64u,
          input.custodyLineageB64u,
          input.grantNonceB64u,
          input.grantKeyId,
          input.grantB64u,
          input.grantDigestB64u,
          input.issuedAtMs,
          input.expiresAtMs,
          timestamp,
        )
        .run();

      const stored = await readByOperation(database, namespace, input.operationId);
      if (!stored) {
        throw new TenantRootCreationGrantStoreError(
          'identity_lineage_exists',
          'tenant-root identity already has an initial custody lineage',
        );
      }
      if (!sameOperationScope(stored, input)) {
        throw new TenantRootCreationGrantStoreError(
          'grant_operation_conflict',
          'tenant-root creation operation raced with a different grant',
        );
      }
      return stored;
    },

    async markActiveFromReady(rawInput: TenantRootCreationGrantReadyInputV1) {
      const input = {
        operationId: requiredText(rawInput.operationId, 'operationId'),
        identity: normalizeIdentity(rawInput.identity),
        identityDigestB64u: requiredText(rawInput.identityDigestB64u, 'identityDigestB64u'),
        custodyLineageB64u: requiredText(rawInput.custodyLineageB64u, 'custodyLineageB64u'),
        ready: {
          revision: positiveSafeInteger(rawInput.ready.revision, 'ready.revision'),
          rootCommitmentB64u: requiredText(
            rawInput.ready.rootCommitmentB64u,
            'ready.rootCommitmentB64u',
          ),
          journalDigestB64u: requiredText(
            rawInput.ready.journalDigestB64u,
            'ready.journalDigestB64u',
          ),
          capabilityDigestB64u: requiredText(
            rawInput.ready.capabilityDigestB64u,
            'ready.capabilityDigestB64u',
          ),
        },
      };
      const existing = await readByOperation(database, namespace, input.operationId);
      if (!existing) {
        throw new TenantRootCreationGrantStoreError(
          'grant_not_found',
          'tenant-root creation operation was not found',
        );
      }
      if (
        !sameIdentity(existing.identity, input.identity) ||
        existing.identityDigestB64u !== input.identityDigestB64u ||
        existing.custodyLineageB64u !== input.custodyLineageB64u
      ) {
        throw new TenantRootCreationGrantStoreError(
          'identity_mismatch',
          'tenant-root ready response does not match the issued grant',
        );
      }
      if (existing.status === 'ACTIVE') {
        if (!sameReady(existing.ready, input.ready)) {
          throw new TenantRootCreationGrantStoreError(
            'ready_conflict',
            'tenant-root creation operation is already active with a different result',
          );
        }
        return existing;
      }

      const result = await database
        .prepare(
          `UPDATE tenant_root_creation_grants
           SET status = 'ACTIVE', active_revision = ?1, root_commitment_b64u = ?2,
               journal_digest_b64u = ?3, capability_digest_b64u = ?4, updated_at_ms = ?5
           WHERE namespace = ?6 AND operation_id = ?7 AND status = 'ISSUED'
             AND identity_digest_b64u = ?8 AND custody_lineage_b64u = ?9`,
        )
        .bind(
          input.ready.revision,
          input.ready.rootCommitmentB64u,
          input.ready.journalDigestB64u,
          input.ready.capabilityDigestB64u,
          positiveSafeInteger(now().getTime(), 'current time'),
          namespace,
          input.operationId,
          input.identityDigestB64u,
          input.custodyLineageB64u,
        )
        .run();
      const stored = await readByOperation(database, namespace, input.operationId);
      if (!stored || stored.status !== 'ACTIVE') {
        throw new TenantRootCreationGrantStoreError(
          'ready_conflict',
          'tenant-root creation operation could not transition to active',
        );
      }
      if (d1ChangedRows(result) === 0 && !sameReady(stored.ready, input.ready)) {
        throw new TenantRootCreationGrantStoreError(
          'ready_conflict',
          'tenant-root creation operation raced with a different active result',
        );
      }
      return stored;
    },

    async findActiveLineageByIdentity(rawInput: TenantRootActiveLineageLookupV1) {
      const input = {
        identity: normalizeIdentity(rawInput.identity),
        identityDigestB64u: requiredText(rawInput.identityDigestB64u, 'identityDigestB64u'),
      };
      const row = await queryD1One(
        database,
        `SELECT * FROM tenant_root_creation_grants
         WHERE namespace = ?1 AND identity_digest_b64u = ?2 AND status = 'ACTIVE'`,
        [namespace, input.identityDigestB64u],
      );
      if (!row) return null;
      const record = parseRecord(row);
      if (!sameIdentity(record.identity, input.identity)) {
        throw new TenantRootCreationGrantStoreError(
          'invalid_record',
          'tenant-root active identity digest resolves to different canonical fields',
        );
      }
      return record;
    },
  };
}

import type {
  TenantRootActiveLineageLookupV1,
  TenantRootCreationGrantIssueV1,
  TenantRootCreationGrantReadyInputV1,
  TenantRootCreationGrantRecordV1,
  TenantRootCreationGrantStoreV1,
} from './types';

export type TenantRootCreationGrantStoreErrorCodeV1 =
  | 'invalid_input'
  | 'grant_operation_conflict'
  | 'identity_lineage_exists'
  | 'grant_not_found'
  | 'identity_mismatch'
  | 'ready_conflict'
  | 'invalid_record';

export class TenantRootCreationGrantStoreError extends Error {
  readonly code: TenantRootCreationGrantStoreErrorCodeV1;
  readonly statusCode: 400 | 404 | 409 | 500;

  constructor(code: TenantRootCreationGrantStoreErrorCodeV1, message: string) {
    super(message);
    this.name = 'TenantRootCreationGrantStoreError';
    this.code = code;
    this.statusCode = tenantRootCreationGrantStoreErrorStatus(code);
  }
}

function tenantRootCreationGrantStoreErrorStatus(
  code: TenantRootCreationGrantStoreErrorCodeV1,
): 400 | 404 | 409 | 500 {
  switch (code) {
    case 'invalid_input':
      return 400;
    case 'grant_not_found':
      return 404;
    case 'grant_operation_conflict':
    case 'identity_lineage_exists':
    case 'identity_mismatch':
    case 'ready_conflict':
      return 409;
    case 'invalid_record':
      return 500;
  }
}

export function isTenantRootCreationGrantStoreError(
  error: unknown,
): error is TenantRootCreationGrantStoreError {
  return error instanceof TenantRootCreationGrantStoreError;
}

export interface TenantRootCreationGrantServiceV1 extends TenantRootCreationGrantStoreV1 {
  findGrantByOperationId(operationId: string): Promise<TenantRootCreationGrantRecordV1 | null>;
  putOrGetGrant(input: TenantRootCreationGrantIssueV1): Promise<TenantRootCreationGrantRecordV1>;
  markActiveFromReady(
    input: TenantRootCreationGrantReadyInputV1,
  ): Promise<TenantRootCreationGrantRecordV1>;
  findActiveLineageByIdentity(
    input: TenantRootActiveLineageLookupV1,
  ): Promise<TenantRootCreationGrantRecordV1 | null>;
}

import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleApprovalsError } from './errors';
import type {
  ApproveConsoleApprovalRequest,
  ConsoleApprovalOperationType,
  ConsoleApprovalStatus,
  CreateConsoleApprovalRequest,
  ListConsoleApprovalsRequest,
  RejectConsoleApprovalRequest,
} from './types';

const APPROVAL_OPERATION_TYPES = new Set<ConsoleApprovalOperationType>([
  'POLICY_PUBLISH',
  'KEY_EXPORT',
  'SECURITY_SETTINGS_CHANGE',
]);
const APPROVAL_STATUSES = new Set<ConsoleApprovalStatus>([
  'PENDING',
  'APPROVED',
  'REJECTED',
  'CANCELED',
]);

function createError(code: string, status: number, message: string): ConsoleApprovalsError {
  return new ConsoleApprovalsError(code, status, message);
}

function parseOperationType(raw: unknown): ConsoleApprovalOperationType | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleApprovalOperationType;
  if (!APPROVAL_OPERATION_TYPES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field operationType must be one of: ${Array.from(APPROVAL_OPERATION_TYPES).join(', ')}`,
    );
  }
  return value;
}

function parseStatus(raw: unknown): ConsoleApprovalStatus | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleApprovalStatus;
  if (!APPROVAL_STATUSES.has(value)) {
    throw createError(
      'invalid_query',
      400,
      `Query status must be one of: ${Array.from(APPROVAL_STATUSES).join(', ')}`,
    );
  }
  return value;
}

function parseRequiredApprovals(raw: unknown): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw createError('invalid_body', 400, 'Field requiredApprovals must be a positive integer');
  }
  return value;
}

function parseOptionalBoolean(raw: unknown, field: string): boolean | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw === 'boolean') return raw;
  const value = String(raw).trim().toLowerCase();
  if (value === 'true' || value === '1') return true;
  if (value === 'false' || value === '0') return false;
  throw createError('invalid_body', 400, `Field ${field} must be a boolean`);
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field metadata must be an object');
  }
  return raw as Record<string, unknown>;
}

export function parseListConsoleApprovalsRequest(query: unknown): ListConsoleApprovalsRequest {
  const obj = requireQueryObject(query, createError);
  const status = parseStatus(readOptionalQueryString(obj, 'status'));
  const operationType = parseOperationType(readOptionalQueryString(obj, 'operationType'));
  return {
    ...(status ? { status } : {}),
    ...(operationType ? { operationType } : {}),
    ...(readOptionalQueryString(obj, 'projectId')
      ? { projectId: readOptionalQueryString(obj, 'projectId') }
      : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
  };
}

export function parseCreateConsoleApprovalRequest(body: unknown): CreateConsoleApprovalRequest {
  const obj = requireObject(body, createError);
  const operationType = parseOperationType(obj.operationType);
  if (!operationType) {
    throw createError('invalid_body', 400, 'Missing required field: operationType');
  }
  const requiredApprovals = parseRequiredApprovals(obj.requiredApprovals);
  const requireMfa = parseOptionalBoolean(obj.requireMfa, 'requireMfa');
  const metadata = parseMetadata(obj.metadata);
  return {
    ...(readOptionalString(obj, 'id') ? { id: readOptionalString(obj, 'id') } : {}),
    operationType,
    reason: readRequiredString(obj, 'reason', createError),
    ...(requiredApprovals !== undefined ? { requiredApprovals } : {}),
    ...(requireMfa !== undefined ? { requireMfa } : {}),
    ...(readOptionalString(obj, 'projectId') ? { projectId: readOptionalString(obj, 'projectId') } : {}),
    ...(readOptionalString(obj, 'environmentId')
      ? { environmentId: readOptionalString(obj, 'environmentId') }
      : {}),
    ...(readOptionalString(obj, 'resourceType')
      ? { resourceType: readOptionalString(obj, 'resourceType') }
      : {}),
    ...(readOptionalString(obj, 'resourceId') ? { resourceId: readOptionalString(obj, 'resourceId') } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

export function parseApproveConsoleApprovalRequest(body: unknown): ApproveConsoleApprovalRequest {
  const obj = requireObject(body, createError);
  return {
    reason: readRequiredString(obj, 'reason', createError),
    mfaVerified: parseOptionalBoolean(obj.mfaVerified, 'mfaVerified') === true,
  };
}

export function parseRejectConsoleApprovalRequest(body: unknown): RejectConsoleApprovalRequest {
  const obj = requireObject(body, createError);
  return {
    reason: readRequiredString(obj, 'reason', createError),
  };
}

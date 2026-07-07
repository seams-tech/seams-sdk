import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleEnterpriseIsolationError } from './errors';
import type {
  ConsoleEnterpriseIsolationScope,
  ConsoleEnterpriseIsolationTrigger,
  GetConsoleEnterpriseIsolationRequest,
  TriggerConsoleEnterpriseIsolationRequest,
} from './types';

const SCOPE_SET = new Set<ConsoleEnterpriseIsolationScope>(['ORG', 'PROJECT', 'ENVIRONMENT']);
const TRIGGER_SET = new Set<ConsoleEnterpriseIsolationTrigger>(['MANUAL', 'SLA_BREACH', 'COMPLIANCE']);

function createError(code: string, status: number, message: string): ConsoleEnterpriseIsolationError {
  return new ConsoleEnterpriseIsolationError(code, status, message);
}

function parseOptionalScope(
  raw: unknown,
  source: 'query' | 'body',
): ConsoleEnterpriseIsolationScope | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleEnterpriseIsolationScope;
  if (!SCOPE_SET.has(value)) {
    throw createError(
      source === 'query' ? 'invalid_query' : 'invalid_body',
      400,
      `Field scope must be one of: ${Array.from(SCOPE_SET).join(', ')}`,
    );
  }
  return value;
}

function parseOptionalTrigger(raw: unknown): ConsoleEnterpriseIsolationTrigger | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleEnterpriseIsolationTrigger;
  if (!TRIGGER_SET.has(value)) {
    throw createError('invalid_body', 400, `Field trigger must be one of: ${Array.from(TRIGGER_SET).join(', ')}`);
  }
  return value;
}

function assertScopeIdentifiers(
  scope: ConsoleEnterpriseIsolationScope,
  input: { projectId?: string; environmentId?: string },
): void {
  if (scope === 'PROJECT' && !input.projectId) {
    throw createError('invalid_body', 400, 'Field projectId is required when scope=PROJECT');
  }
  if (scope === 'ENVIRONMENT' && (!input.projectId || !input.environmentId)) {
    throw createError(
      'invalid_body',
      400,
      'Fields projectId and environmentId are required when scope=ENVIRONMENT',
    );
  }
}

export function parseGetConsoleEnterpriseIsolationRequest(
  query: unknown,
): GetConsoleEnterpriseIsolationRequest {
  const obj = requireQueryObject(query, createError);
  const scope = parseOptionalScope(readOptionalQueryString(obj, 'scope'), 'query');
  const projectId = readOptionalQueryString(obj, 'projectId');
  const environmentId = readOptionalQueryString(obj, 'environmentId');
  if (scope) {
    assertScopeIdentifiers(scope, { projectId, environmentId });
  }
  return {
    ...(scope ? { scope } : {}),
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
  };
}

export function parseTriggerConsoleEnterpriseIsolationRequest(
  body: unknown,
): TriggerConsoleEnterpriseIsolationRequest {
  const obj = requireObject(body, createError);
  const scope = parseOptionalScope(readOptionalString(obj, 'scope'), 'body') || 'ORG';
  const projectId = readOptionalString(obj, 'projectId');
  const environmentId = readOptionalString(obj, 'environmentId');
  assertScopeIdentifiers(scope, { projectId, environmentId });
  const trigger = parseOptionalTrigger(readOptionalString(obj, 'trigger')) || 'MANUAL';
  return {
    scope,
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    trigger,
    reason: readRequiredString(obj, 'reason', createError),
    ...(readOptionalString(obj, 'ticketId') ? { ticketId: readOptionalString(obj, 'ticketId') } : {}),
  };
}

import { ConsolePolicyError } from './errors';
import { parseConsolePolicyRulesInput } from './rules';
import {
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
} from '../shared/requestParse';
import type {
  CreateConsolePolicyRequest,
  ListConsolePolicyAssignmentsRequest,
  SimulateConsolePolicyRequest,
  UpsertConsolePolicyAssignmentRequest,
  UpdateConsolePolicyRequest,
} from './types';

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;
const ASSIGNMENT_SCOPE_TYPES = new Set(['ORG', 'PROJECT', 'ENVIRONMENT', 'WALLET']);

function createParseError(code: string, status: number, message: string): ConsolePolicyError {
  return new ConsolePolicyError(code, status, message);
}

function readOptionalResourceId(body: Record<string, unknown>, key: string): string | undefined {
  const value = readOptionalString(body, key);
  if (!value) return undefined;
  if (!RESOURCE_ID_PATTERN.test(value)) {
    throw new ConsolePolicyError(
      'invalid_body',
      400,
      `Field ${key} may only contain letters, numbers, colon, underscore, and hyphen`,
    );
  }
  return value;
}

function readOptionalRules(
  body: Record<string, unknown>,
  key: string,
): CreateConsolePolicyRequest['rules'] | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  return parseConsolePolicyRulesInput(raw);
}

function readOptionalInteger(
  body: Record<string, unknown>,
  key: string,
): number | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(n)) {
    throw new ConsolePolicyError('invalid_body', 400, `Field ${key} must be an integer`);
  }
  return n;
}

export function parseCreateConsolePolicyRequest(body: unknown): CreateConsolePolicyRequest {
  const obj = requireObject(body, createParseError);
  const id = readOptionalResourceId(obj, 'id');
  const name = readRequiredString(obj, 'name', createParseError);
  const description = readOptionalString(obj, 'description');
  const rules = readOptionalRules(obj, 'rules');
  return {
    ...(id ? { id } : {}),
    name,
    ...(description ? { description } : {}),
    ...(rules ? { rules } : {}),
  };
}

export function parseUpdateConsolePolicyRequest(body: unknown): UpdateConsolePolicyRequest {
  const obj = requireObject(body, createParseError);
  const name = readOptionalString(obj, 'name');
  const description = readOptionalString(obj, 'description');
  const rules = readOptionalRules(obj, 'rules');
  if (!name && !description && !rules) {
    throw new ConsolePolicyError(
      'invalid_body',
      400,
      'At least one mutable field is required',
    );
  }
  return {
    ...(name ? { name } : {}),
    ...(description ? { description } : {}),
    ...(rules ? { rules } : {}),
  };
}

export function parseSimulateConsolePolicyRequest(body: unknown): SimulateConsolePolicyRequest {
  const obj = requireObject(body, createParseError);
  const action = readRequiredString(obj, 'action', createParseError);
  const chain = readOptionalString(obj, 'chain');
  const amountMinor = readOptionalInteger(obj, 'amountMinor');
  const contractAddress = readOptionalString(obj, 'contractAddress');
  const functionSelector = readOptionalString(obj, 'functionSelector');
  if (amountMinor !== undefined && amountMinor < 0) {
    throw new ConsolePolicyError('invalid_body', 400, 'Field amountMinor must be >= 0');
  }
  const metadataRaw = obj.metadata;
  if (
    metadataRaw !== undefined &&
    metadataRaw !== null &&
    (!metadataRaw || typeof metadataRaw !== 'object' || Array.isArray(metadataRaw))
  ) {
    throw new ConsolePolicyError('invalid_body', 400, 'Field metadata must be a JSON object');
  }
  return {
    action,
    ...(chain ? { chain } : {}),
    ...(amountMinor !== undefined ? { amountMinor } : {}),
    ...(contractAddress ? { contractAddress } : {}),
    ...(functionSelector ? { functionSelector } : {}),
    ...(metadataRaw && typeof metadataRaw === 'object' && !Array.isArray(metadataRaw)
      ? { metadata: metadataRaw as Record<string, unknown> }
      : {}),
  };
}

function readOptionalScopeType(raw: unknown): string | undefined {
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw || '')
    .trim()
    .toUpperCase();
  if (!value) return undefined;
  if (!ASSIGNMENT_SCOPE_TYPES.has(value)) {
    throw new ConsolePolicyError(
      'invalid_query',
      400,
      'Field scopeType must be one of ORG, PROJECT, ENVIRONMENT, WALLET',
    );
  }
  return value;
}

export function parseListConsolePolicyAssignmentsRequest(
  query: unknown,
): ListConsolePolicyAssignmentsRequest {
  if (!query || typeof query !== 'object' || Array.isArray(query)) return {};
  const row = query as Record<string, unknown>;
  const scopeType = readOptionalScopeType(row.scopeType);
  const scopeIdRaw = row.scopeId;
  const scopeId = scopeIdRaw == null ? undefined : String(scopeIdRaw || '').trim() || undefined;
  if (scopeId && !RESOURCE_ID_PATTERN.test(scopeId)) {
    throw new ConsolePolicyError(
      'invalid_query',
      400,
      'Field scopeId may only contain letters, numbers, colon, underscore, and hyphen',
    );
  }
  if (scopeId && !scopeType) {
    throw new ConsolePolicyError('invalid_query', 400, 'scopeType is required when scopeId is provided');
  }
  return {
    ...(scopeType ? { scopeType: scopeType as ListConsolePolicyAssignmentsRequest['scopeType'] } : {}),
    ...(scopeId ? { scopeId } : {}),
  };
}

export function parseUpsertConsolePolicyAssignmentRequest(
  body: unknown,
): UpsertConsolePolicyAssignmentRequest {
  const obj = requireObject(body, createParseError);
  const scopeType = String(readRequiredString(obj, 'scopeType', createParseError) || '')
    .trim()
    .toUpperCase();
  if (!ASSIGNMENT_SCOPE_TYPES.has(scopeType)) {
    throw new ConsolePolicyError(
      'invalid_body',
      400,
      'Field scopeType must be one of ORG, PROJECT, ENVIRONMENT, WALLET',
    );
  }
  const scopeId = readRequiredString(obj, 'scopeId', createParseError);
  if (!RESOURCE_ID_PATTERN.test(scopeId)) {
    throw new ConsolePolicyError(
      'invalid_body',
      400,
      'Field scopeId may only contain letters, numbers, colon, underscore, and hyphen',
    );
  }
  const policyId = readRequiredString(obj, 'policyId', createParseError);
  if (!RESOURCE_ID_PATTERN.test(policyId)) {
    throw new ConsolePolicyError(
      'invalid_body',
      400,
      'Field policyId may only contain letters, numbers, colon, underscore, and hyphen',
    );
  }
  return {
    scopeType: scopeType as UpsertConsolePolicyAssignmentRequest['scopeType'],
    scopeId,
    policyId,
  };
}

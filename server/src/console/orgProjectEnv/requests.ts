import { ConsoleOrgProjectEnvError } from './errors';
import type {
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ListConsoleProjectsRequest,
  ListConsoleEnvironmentsRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;

function requireQueryObject(query: unknown): Record<string, unknown> {
  if (query === undefined || query === null) return {};
  if (!query || typeof query !== 'object' || Array.isArray(query)) {
    throw new ConsoleOrgProjectEnvError('invalid_query', 400, 'Expected query params object');
  }
  return query as Record<string, unknown>;
}

function readOptionalQueryString(query: Record<string, unknown>, key: string): string | undefined {
  const raw = query[key];
  if (raw === undefined || raw === null) return undefined;
  const first = Array.isArray(raw) ? raw[0] : raw;
  const value = String(first).trim();
  return value || undefined;
}

export function parseListConsoleEnvironmentsRequest(
  query: unknown,
): ListConsoleEnvironmentsRequest {
  const obj = requireQueryObject(query);
  const statusRaw = readOptionalQueryString(obj, 'status');
  const status = statusRaw ? statusRaw.toUpperCase() : undefined;
  if (status && status !== 'ACTIVE' && status !== 'ARCHIVED') {
    throw new ConsoleOrgProjectEnvError(
      'invalid_query',
      400,
      'Field status must be one of ACTIVE or ARCHIVED',
    );
  }
  return {
    projectId: readOptionalQueryString(obj, 'projectId'),
    ...(status ? { status: status as ListConsoleEnvironmentsRequest['status'] } : {}),
  };
}

export function parseListConsoleProjectsRequest(query: unknown): ListConsoleProjectsRequest {
  const obj = requireQueryObject(query);
  const statusRaw = readOptionalQueryString(obj, 'status');
  const status = statusRaw ? statusRaw.toUpperCase() : undefined;
  if (status && status !== 'ACTIVE' && status !== 'ARCHIVED') {
    throw new ConsoleOrgProjectEnvError(
      'invalid_query',
      400,
      'Field status must be one of ACTIVE or ARCHIVED',
    );
  }
  return {
    ...(status ? { status: status as ListConsoleProjectsRequest['status'] } : {}),
  };
}

function requireBodyObject(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConsoleOrgProjectEnvError('invalid_body', 400, 'Expected JSON object request body');
  }
  return body as Record<string, unknown>;
}

function readRequiredBodyString(body: Record<string, unknown>, key: string): string {
  const value = String(body[key] ?? '').trim();
  if (!value) {
    throw new ConsoleOrgProjectEnvError('invalid_body', 400, `Missing required field: ${key}`);
  }
  return value;
}

function readOptionalBodyString(body: Record<string, unknown>, key: string): string | undefined {
  const raw = body[key];
  if (raw === undefined || raw === null) return undefined;
  const value = String(raw).trim();
  return value || undefined;
}

function readOptionalResourceId(body: Record<string, unknown>, key: string): string | undefined {
  const value = readOptionalBodyString(body, key);
  if (!value) return undefined;
  if (!RESOURCE_ID_PATTERN.test(value)) {
    throw new ConsoleOrgProjectEnvError(
      'invalid_body',
      400,
      `Field ${key} may only contain letters, numbers, colon, underscore, and hyphen`,
    );
  }
  return value;
}

export function parseCreateConsoleProjectRequest(body: unknown): CreateConsoleProjectRequest {
  const obj = requireBodyObject(body);
  const name = readRequiredBodyString(obj, 'name');
  const id = readOptionalResourceId(obj, 'id');
  return {
    ...(id ? { id } : {}),
    name,
  };
}

export function parseUpdateConsoleProjectRequest(body: unknown): UpdateConsoleProjectRequest {
  const obj = requireBodyObject(body);
  const name = readOptionalBodyString(obj, 'name');
  if (!name) {
    throw new ConsoleOrgProjectEnvError(
      'invalid_body',
      400,
      'At least one mutable field is required',
    );
  }
  return { name };
}

function parseEnvironmentKey(body: Record<string, unknown>): CreateConsoleEnvironmentRequest['key'] {
  const key = readRequiredBodyString(body, 'key').toLowerCase();
  if (key === 'dev' || key === 'staging' || key === 'prod') {
    return key;
  }
  throw new ConsoleOrgProjectEnvError(
    'invalid_body',
    400,
    'Field key must be one of dev, staging, prod',
  );
}

export function parseCreateConsoleEnvironmentRequest(body: unknown): CreateConsoleEnvironmentRequest {
  const obj = requireBodyObject(body);
  const id = readOptionalResourceId(obj, 'id');
  const name = readOptionalBodyString(obj, 'name');
  const projectId = readRequiredBodyString(obj, 'projectId');
  if (!RESOURCE_ID_PATTERN.test(projectId)) {
    throw new ConsoleOrgProjectEnvError(
      'invalid_body',
      400,
      'Field projectId may only contain letters, numbers, colon, underscore, and hyphen',
    );
  }
  return {
    ...(id ? { id } : {}),
    projectId,
    key: parseEnvironmentKey(obj),
    ...(name ? { name } : {}),
  };
}

export function parseUpdateConsoleEnvironmentRequest(body: unknown): UpdateConsoleEnvironmentRequest {
  const obj = requireBodyObject(body);
  const name = readOptionalBodyString(obj, 'name');
  if (!name) {
    throw new ConsoleOrgProjectEnvError(
      'invalid_body',
      400,
      'At least one mutable field is required',
    );
  }
  return { name };
}

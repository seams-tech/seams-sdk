import { ConsoleOrgProjectEnvError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  CreateConsoleEnvironmentRequest,
  CreateConsoleProjectRequest,
  ListConsoleProjectsRequest,
  ListConsoleEnvironmentsRequest,
  UpdateConsoleEnvironmentRequest,
  UpdateConsoleProjectRequest,
} from './types';

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;

function createParseError(
  code: string,
  status: number,
  message: string,
): ConsoleOrgProjectEnvError {
  return new ConsoleOrgProjectEnvError(code, status, message);
}

export function parseListConsoleEnvironmentsRequest(
  query: unknown,
): ListConsoleEnvironmentsRequest {
  const obj = requireQueryObject(query, createParseError);
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
  const obj = requireQueryObject(query, createParseError);
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

function readOptionalResourceId(body: Record<string, unknown>, key: string): string | undefined {
  const value = readOptionalString(body, key);
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
  const obj = requireBodyObject(body, createParseError);
  const name = readRequiredString(obj, 'name', createParseError);
  const id = readOptionalResourceId(obj, 'id');
  return {
    ...(id ? { id } : {}),
    name,
  };
}

export function parseUpdateConsoleProjectRequest(body: unknown): UpdateConsoleProjectRequest {
  const obj = requireBodyObject(body, createParseError);
  const name = readOptionalString(obj, 'name');
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
  const key = readRequiredString(body, 'key', createParseError).toLowerCase();
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
  const obj = requireBodyObject(body, createParseError);
  const id = readOptionalResourceId(obj, 'id');
  const name = readOptionalString(obj, 'name');
  const projectId = readRequiredString(obj, 'projectId', createParseError);
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
  const obj = requireBodyObject(body, createParseError);
  const name = readOptionalString(obj, 'name');
  if (!name) {
    throw new ConsoleOrgProjectEnvError(
      'invalid_body',
      400,
      'At least one mutable field is required',
    );
  }
  return { name };
}

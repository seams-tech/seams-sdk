import {
  readOptionalStringField as readOptionalString,
  readOptionalQueryPositiveIntegerField,
  readRequiredStringField as readRequiredString,
  requireBodyObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleOnboardingError } from './errors';
import type {
  ConsoleOnboardingOrgInput,
  ConsoleOnboardingProjectInput,
  CreateConsoleOnboardingOrganizationRequest,
  CreateConsoleOnboardingProjectRequest,
  GetConsoleOnboardingTelemetryRequest,
  GetConsoleOnboardingStateRequest,
} from './types';

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;
const MIN_TELEMETRY_WINDOW_MINUTES = 1;
const MAX_TELEMETRY_WINDOW_MINUTES = 24 * 60;

function createParseError(code: string, status: number, message: string): ConsoleOnboardingError {
  return new ConsoleOnboardingError(code, status, message);
}

function readObjectField(
  source: Record<string, unknown>,
  key: string,
): Record<string, unknown> {
  const raw = source[key];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createParseError('invalid_body', 400, `Field ${key} must be an object`);
  }
  return raw as Record<string, unknown>;
}

function readOptionalResourceId(source: Record<string, unknown>, key: string): string | undefined {
  const value = readOptionalString(source, key);
  if (!value) return undefined;
  if (!RESOURCE_ID_PATTERN.test(value)) {
    throw createParseError(
      'invalid_body',
      400,
      `Field ${key} may only contain letters, numbers, colon, underscore, and hyphen`,
    );
  }
  return value;
}

function parseOptionalOrgInput(source: Record<string, unknown>): ConsoleOnboardingOrgInput | undefined {
  if (source.org === undefined || source.org === null) return undefined;
  const row = readObjectField(source, 'org');
  const name = readRequiredString(row, 'name', createParseError);
  const slug = readOptionalString(row, 'slug');
  return {
    name,
    ...(slug ? { slug } : {}),
  };
}

function parseProjectInput(source: Record<string, unknown>): ConsoleOnboardingProjectInput {
  const row = readObjectField(source, 'project');
  const name = readRequiredString(row, 'name', createParseError);
  const id = readOptionalResourceId(row, 'id');
  return {
    ...(id ? { id } : {}),
    name,
  };
}

export function parseGetConsoleOnboardingStateRequest(
  query: unknown,
): GetConsoleOnboardingStateRequest {
  requireQueryObject(query, createParseError);
  return {};
}

export function parseGetConsoleOnboardingTelemetryRequest(
  query: unknown,
): GetConsoleOnboardingTelemetryRequest {
  const q = requireQueryObject(query, createParseError);
  const windowMinutes = readOptionalQueryPositiveIntegerField(
    q,
    'windowMinutes',
    createParseError,
  );
  if (windowMinutes === undefined) return {};
  if (
    windowMinutes < MIN_TELEMETRY_WINDOW_MINUTES ||
    windowMinutes > MAX_TELEMETRY_WINDOW_MINUTES
  ) {
    throw createParseError(
      'invalid_query',
      400,
      `Query parameter windowMinutes must be between ${MIN_TELEMETRY_WINDOW_MINUTES} and ${MAX_TELEMETRY_WINDOW_MINUTES}`,
    );
  }
  return { windowMinutes };
}

export function parseCreateConsoleOnboardingProjectRequest(
  body: unknown,
): CreateConsoleOnboardingProjectRequest {
  const source = requireBodyObject(body, createParseError);
  const project = parseProjectInput(source);
  const environmentRaw = source.environment;
  if (environmentRaw === undefined || environmentRaw === null) {
    return { project };
  }
  if (typeof environmentRaw !== 'object' || Array.isArray(environmentRaw)) {
    throw createParseError('invalid_body', 400, 'Field environment must be an object');
  }
  const environmentRow = environmentRaw as Record<string, unknown>;
  const environmentId = readOptionalResourceId(environmentRow, 'id');
  const environmentName = readOptionalString(environmentRow, 'name');
  return {
    project,
    environment: {
      ...(environmentId ? { id: environmentId } : {}),
      ...(environmentName ? { name: environmentName } : {}),
    },
  };
}

export function parseCreateConsoleOnboardingOrganizationRequest(
  body: unknown,
): CreateConsoleOnboardingOrganizationRequest {
  const source = requireBodyObject(body, createParseError);
  const org = parseOptionalOrgInput(source);
  if (!org) {
    throw createParseError('invalid_body', 400, 'Field org is required');
  }
  return { org };
}

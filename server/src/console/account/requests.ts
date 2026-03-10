import {
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject,
} from '../shared/requestParse';
import { ConsoleAccountError } from './errors';
import type {
  CreateConsoleAccountOrganizationRequest,
  PatchConsoleAccountProfileRequest,
  TransferConsoleAccountOrganizationOwnerRequest,
  UpdateConsoleAccountOrganizationRequest,
} from './types';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;

function createParseError(code: string, status: number, message: string): ConsoleAccountError {
  return new ConsoleAccountError(code, status, message);
}

function readOptionalEmail(source: Record<string, unknown>, key: string): string | undefined {
  const value = readOptionalString(source, key);
  if (!value) return undefined;
  const normalized = value.toLowerCase();
  if (!EMAIL_PATTERN.test(normalized)) {
    throw createParseError('invalid_body', 400, `Field ${key} must be a valid email address`);
  }
  return normalized;
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

export function parsePatchConsoleAccountProfileRequest(
  body: unknown,
): PatchConsoleAccountProfileRequest {
  const source = requireBodyObject(body, createParseError);
  const displayName = readOptionalString(source, 'displayName');
  const primaryEmail = readOptionalEmail(source, 'primaryEmail');
  const addBackupEmail = readOptionalEmail(source, 'addBackupEmail');
  const removeBackupEmail = readOptionalEmail(source, 'removeBackupEmail');
  if (!displayName && !primaryEmail && !addBackupEmail && !removeBackupEmail) {
    throw createParseError('invalid_body', 400, 'At least one mutable field is required');
  }
  return {
    ...(displayName ? { displayName } : {}),
    ...(primaryEmail ? { primaryEmail } : {}),
    ...(addBackupEmail ? { addBackupEmail } : {}),
    ...(removeBackupEmail ? { removeBackupEmail } : {}),
  };
}

export function parseCreateConsoleAccountOrganizationRequest(
  body: unknown,
): CreateConsoleAccountOrganizationRequest {
  const source = requireBodyObject(body, createParseError);
  const name = readRequiredString(source, 'name', createParseError);
  const id = readOptionalResourceId(source, 'id');
  const slug = readOptionalString(source, 'slug');
  return {
    name,
    ...(id ? { id } : {}),
    ...(slug ? { slug } : {}),
  };
}

export function parseUpdateConsoleAccountOrganizationRequest(
  body: unknown,
): UpdateConsoleAccountOrganizationRequest {
  const source = requireBodyObject(body, createParseError);
  const name = readOptionalString(source, 'name');
  const slug = readOptionalString(source, 'slug');
  if (!name && !slug) {
    throw createParseError('invalid_body', 400, 'At least one mutable field is required');
  }
  return {
    ...(name ? { name } : {}),
    ...(slug ? { slug } : {}),
  };
}

export function parseTransferConsoleAccountOrganizationOwnerRequest(
  body: unknown,
): TransferConsoleAccountOrganizationOwnerRequest {
  const source = requireBodyObject(body, createParseError);
  const targetMemberId = readOptionalResourceId(source, 'targetMemberId');
  const targetUserId = readOptionalString(source, 'targetUserId');
  if (!targetMemberId && !targetUserId) {
    throw createParseError(
      'invalid_body',
      400,
      'Either targetMemberId or targetUserId is required',
    );
  }
  return {
    ...(targetMemberId ? { targetMemberId } : {}),
    ...(targetUserId ? { targetUserId } : {}),
  };
}

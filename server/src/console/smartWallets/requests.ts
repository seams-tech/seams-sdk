import { ConsoleSmartWalletError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleSmartWalletAccountType,
  ConsoleSmartWalletBundlerConfig,
  ConsoleSmartWalletEntryPointVersion,
  ConsoleSmartWalletFallbackBehavior,
  ConsoleSmartWalletMode,
  ConsoleSmartWalletPaymasterMode,
  ConsoleSmartWalletScopeType,
  CreateConsoleSmartWalletRequest,
  ListConsoleSmartWalletRequest,
  UpdateConsoleSmartWalletRequest,
} from './types';

const SMART_WALLET_SCOPE_TYPES = new Set<ConsoleSmartWalletScopeType>([
  'ORG',
  'PROJECT',
  'ENVIRONMENT',
  'POLICY',
  'WALLET_SEGMENT',
]);
const SMART_WALLET_MODES = new Set<ConsoleSmartWalletMode>(['DISABLED', 'OPTIONAL', 'REQUIRED']);
const SMART_WALLET_ACCOUNT_TYPES = new Set<ConsoleSmartWalletAccountType>(['EOA', 'SMART_ACCOUNT']);
const SMART_WALLET_PAYMASTER_MODES = new Set<ConsoleSmartWalletPaymasterMode>([
  'DISABLED',
  'AUTO',
  'REQUIRED',
]);
const SMART_WALLET_FALLBACK_BEHAVIORS = new Set<ConsoleSmartWalletFallbackBehavior>([
  'FAIL_CLOSED',
  'FALLBACK_TO_EOA',
]);
const SMART_WALLET_ENTRYPOINT_VERSIONS = new Set<ConsoleSmartWalletEntryPointVersion>([
  'v0.6',
  'v0.7',
]);

function createError(code: string, status: number, message: string): ConsoleSmartWalletError {
  return new ConsoleSmartWalletError(code, status, message);
}

function parseScopeType(raw: unknown): ConsoleSmartWalletScopeType | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleSmartWalletScopeType;
  if (!SMART_WALLET_SCOPE_TYPES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field scopeType must be one of: ${Array.from(SMART_WALLET_SCOPE_TYPES).join(', ')}`,
    );
  }
  return value;
}

function parseMode(raw: unknown): ConsoleSmartWalletMode | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleSmartWalletMode;
  if (!SMART_WALLET_MODES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field mode must be one of: ${Array.from(SMART_WALLET_MODES).join(', ')}`,
    );
  }
  return value;
}

function parseAccountType(raw: unknown): ConsoleSmartWalletAccountType | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleSmartWalletAccountType;
  if (!SMART_WALLET_ACCOUNT_TYPES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field accountType must be one of: ${Array.from(SMART_WALLET_ACCOUNT_TYPES).join(', ')}`,
    );
  }
  return value;
}

function parsePaymasterMode(raw: unknown): ConsoleSmartWalletPaymasterMode | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleSmartWalletPaymasterMode;
  if (!SMART_WALLET_PAYMASTER_MODES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field paymasterMode must be one of: ${Array.from(SMART_WALLET_PAYMASTER_MODES).join(', ')}`,
    );
  }
  return value;
}

function parseFallbackBehavior(raw: unknown): ConsoleSmartWalletFallbackBehavior | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleSmartWalletFallbackBehavior;
  if (!SMART_WALLET_FALLBACK_BEHAVIORS.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field fallbackBehavior must be one of: ${Array.from(SMART_WALLET_FALLBACK_BEHAVIORS).join(', ')}`,
    );
  }
  return value;
}

function parseOptionalBoolean(raw: unknown, field: string): boolean | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw === 'boolean') return raw;
  const text = String(raw).trim().toLowerCase();
  if (text === 'true' || text === '1') return true;
  if (text === 'false' || text === '0') return false;
  throw createError('invalid_body', 400, `Field ${field} must be a boolean`);
}

function parsePositiveNumber(raw: unknown, field: string): number {
  const n = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw createError('invalid_body', 400, `Field ${field} must be a non-negative number`);
  }
  return n;
}

function parseBundler(raw: unknown): ConsoleSmartWalletBundlerConfig | null | undefined {
  if (raw === undefined) return undefined;
  if (raw === null) return null;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field bundler must be an object or null');
  }
  const row = raw as Record<string, unknown>;
  const provider = String(row.provider || '').trim();
  if (!provider) {
    throw createError('invalid_body', 400, 'Field bundler.provider is required');
  }
  const entryPointVersion = String(row.entryPointVersion || '').trim() as ConsoleSmartWalletEntryPointVersion;
  if (!SMART_WALLET_ENTRYPOINT_VERSIONS.has(entryPointVersion)) {
    throw createError(
      'invalid_body',
      400,
      `Field bundler.entryPointVersion must be one of: ${Array.from(SMART_WALLET_ENTRYPOINT_VERSIONS).join(', ')}`,
    );
  }
  return {
    provider,
    entryPointVersion,
    maxFeePerGasGwei: parsePositiveNumber(row.maxFeePerGasGwei, 'bundler.maxFeePerGasGwei'),
    maxPriorityFeePerGasGwei: parsePositiveNumber(
      row.maxPriorityFeePerGasGwei,
      'bundler.maxPriorityFeePerGasGwei',
    ),
  };
}

export function parseListConsoleSmartWalletRequest(query: unknown): ListConsoleSmartWalletRequest {
  const obj = requireQueryObject(query, createError);
  const scopeTypeRaw = readOptionalQueryString(obj, 'scopeType');
  const scopeType = parseScopeType(scopeTypeRaw);
  return {
    ...(scopeType ? { scopeType } : {}),
    ...(readOptionalQueryString(obj, 'projectId') ? { projectId: readOptionalQueryString(obj, 'projectId') } : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    ...(readOptionalQueryString(obj, 'policyId') ? { policyId: readOptionalQueryString(obj, 'policyId') } : {}),
    ...(readOptionalQueryString(obj, 'walletSegmentId')
      ? { walletSegmentId: readOptionalQueryString(obj, 'walletSegmentId') }
      : {}),
  };
}

export function parseCreateConsoleSmartWalletRequest(body: unknown): CreateConsoleSmartWalletRequest {
  const obj = requireObject(body, createError);
  const scopeType = parseScopeType(obj.scopeType);
  if (!scopeType) {
    throw createError('invalid_body', 400, 'Missing required field: scopeType');
  }
  return {
    ...(readOptionalString(obj, 'id') ? { id: readOptionalString(obj, 'id') } : {}),
    scopeType,
    ...(readOptionalString(obj, 'projectId') ? { projectId: readOptionalString(obj, 'projectId') } : {}),
    ...(readOptionalString(obj, 'environmentId')
      ? { environmentId: readOptionalString(obj, 'environmentId') }
      : {}),
    ...(readOptionalString(obj, 'policyId') ? { policyId: readOptionalString(obj, 'policyId') } : {}),
    ...(readOptionalString(obj, 'walletSegmentId')
      ? { walletSegmentId: readOptionalString(obj, 'walletSegmentId') }
      : {}),
    ...(parseOptionalBoolean(obj.enabled, 'enabled') !== undefined
      ? { enabled: parseOptionalBoolean(obj.enabled, 'enabled') }
      : {}),
    ...(parseMode(obj.mode) ? { mode: parseMode(obj.mode) } : {}),
    ...(parseAccountType(obj.accountType) ? { accountType: parseAccountType(obj.accountType) } : {}),
    ...(parsePaymasterMode(obj.paymasterMode) ? { paymasterMode: parsePaymasterMode(obj.paymasterMode) } : {}),
    ...(parseFallbackBehavior(obj.fallbackBehavior)
      ? { fallbackBehavior: parseFallbackBehavior(obj.fallbackBehavior) }
      : {}),
    ...(parseBundler(obj.bundler) !== undefined ? { bundler: parseBundler(obj.bundler) } : {}),
  };
}

export function parseUpdateConsoleSmartWalletRequest(body: unknown): UpdateConsoleSmartWalletRequest {
  const obj = requireObject(body, createError);
  return {
    ...(parseScopeType(obj.scopeType) ? { scopeType: parseScopeType(obj.scopeType) } : {}),
    ...(readOptionalString(obj, 'projectId') ? { projectId: readOptionalString(obj, 'projectId') } : {}),
    ...(readOptionalString(obj, 'environmentId')
      ? { environmentId: readOptionalString(obj, 'environmentId') }
      : {}),
    ...(readOptionalString(obj, 'policyId') ? { policyId: readOptionalString(obj, 'policyId') } : {}),
    ...(readOptionalString(obj, 'walletSegmentId')
      ? { walletSegmentId: readOptionalString(obj, 'walletSegmentId') }
      : {}),
    ...(parseOptionalBoolean(obj.enabled, 'enabled') !== undefined
      ? { enabled: parseOptionalBoolean(obj.enabled, 'enabled') }
      : {}),
    ...(parseMode(obj.mode) ? { mode: parseMode(obj.mode) } : {}),
    ...(parseAccountType(obj.accountType) ? { accountType: parseAccountType(obj.accountType) } : {}),
    ...(parsePaymasterMode(obj.paymasterMode) ? { paymasterMode: parsePaymasterMode(obj.paymasterMode) } : {}),
    ...(parseFallbackBehavior(obj.fallbackBehavior)
      ? { fallbackBehavior: parseFallbackBehavior(obj.fallbackBehavior) }
      : {}),
    ...(parseBundler(obj.bundler) !== undefined ? { bundler: parseBundler(obj.bundler) } : {}),
  };
}

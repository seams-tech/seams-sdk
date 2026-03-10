import { ConsoleGasSponsorshipError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipNetworkClass,
  ConsoleGasSponsorshipScopeType,
  ConsoleGasSponsorshipSpendCap,
  ConsoleGasSponsorshipSpendCapMode,
  ConsoleGasSponsorshipSpendCapPeriod,
  CreateConsoleGasSponsorshipRequest,
  ListConsoleGasSponsorshipRequest,
  UpdateConsoleGasSponsorshipRequest,
} from './types';

const GAS_SCOPE_TYPES = new Set<ConsoleGasSponsorshipScopeType>([
  'ORG',
  'PROJECT',
  'ENVIRONMENT',
  'POLICY',
  'WALLET_SEGMENT',
]);
const GAS_NETWORK_CLASSES = new Set<ConsoleGasSponsorshipNetworkClass>([
  'ANY',
  'TESTNET',
  'MAINNET',
]);
const GAS_CALL_MODES = new Set<ConsoleGasSponsorshipCallMode>(['ALLOW_ALL', 'ALLOWLIST']);
const GAS_SPEND_CAP_MODES = new Set<ConsoleGasSponsorshipSpendCapMode>([
  'NONE',
  'CHAIN_TOTAL',
  'WALLET_CHAIN_TOTAL',
]);
const GAS_SPEND_CAP_PERIODS = new Set<ConsoleGasSponsorshipSpendCapPeriod>([
  'WEEKLY',
  'MONTHLY',
]);

function createError(code: string, status: number, message: string): ConsoleGasSponsorshipError {
  return new ConsoleGasSponsorshipError(code, status, message);
}

function parseScopeType(raw: unknown, field: string): ConsoleGasSponsorshipScopeType | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipScopeType;
  if (!GAS_SCOPE_TYPES.has(value)) {
    throw createError('invalid_body', 400, `Field ${field} must be one of: ${Array.from(GAS_SCOPE_TYPES).join(', ')}`);
  }
  return value;
}

function parseRequiredSpendCapMode(raw: unknown, field: string): ConsoleGasSponsorshipSpendCapMode {
  const value = String(raw || '')
    .trim()
    .toUpperCase() as ConsoleGasSponsorshipSpendCapMode;
  if (!GAS_SPEND_CAP_MODES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field ${field} must be one of: ${Array.from(GAS_SPEND_CAP_MODES).join(', ')}`,
    );
  }
  return value;
}

function parseRequiredSpendCapPeriod(
  raw: unknown,
  field: string,
): ConsoleGasSponsorshipSpendCapPeriod {
  const value = String(raw || '')
    .trim()
    .toUpperCase() as ConsoleGasSponsorshipSpendCapPeriod;
  if (!GAS_SPEND_CAP_PERIODS.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field ${field} must be one of: ${Array.from(GAS_SPEND_CAP_PERIODS).join(', ')}`,
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

function parseOptionalInteger(raw: unknown, field: string): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    throw createError('invalid_body', 400, `Field ${field} must be a non-negative integer`);
  }
  return value;
}

function parseOptionalNetworkClass(raw: unknown): ConsoleGasSponsorshipNetworkClass | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipNetworkClass;
  if (!GAS_NETWORK_CLASSES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field networkClass must be one of: ${Array.from(GAS_NETWORK_CLASSES).join(', ')}`,
    );
  }
  return value;
}

function parseOptionalCallMode(raw: unknown): ConsoleGasSponsorshipCallMode | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipCallMode;
  if (!GAS_CALL_MODES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field callMode must be one of: ${Array.from(GAS_CALL_MODES).join(', ')}`,
    );
  }
  return value;
}

function parseAllowedChainIds(raw: unknown): number[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field allowedChainIds must be an array');
  }
  const out: number[] = [];
  const seen = new Set<number>();
  for (const entry of raw) {
    const chainId = parseOptionalInteger(entry, 'allowedChainIds[]');
    if (!chainId || chainId <= 0) {
      throw createError('invalid_body', 400, 'Field allowedChainIds[] must be a positive integer');
    }
    if (seen.has(chainId)) continue;
    seen.add(chainId);
    out.push(chainId);
  }
  return out;
}

function parseSpendCap(raw: unknown): ConsoleGasSponsorshipSpendCap | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field spendCap must be an object');
  }
  const row = raw as Record<string, unknown>;
  const mode = parseRequiredSpendCapMode(row.mode, 'spendCap.mode');
  const period = parseRequiredSpendCapPeriod(row.period, 'spendCap.period');
  const capsRaw = row.capsByChain;
  if (capsRaw === undefined || capsRaw === null) {
    return {
      mode,
      period,
      capsByChain: [],
    };
  }
  if (!Array.isArray(capsRaw)) {
    throw createError('invalid_body', 400, 'Field spendCap.capsByChain must be an array');
  }
  const out: ConsoleGasSponsorshipSpendCap['capsByChain'] = [];
  const seen = new Set<number>();
  for (const entry of capsRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw createError('invalid_body', 400, 'Field spendCap.capsByChain must contain objects');
    }
    const capRow = entry as Record<string, unknown>;
    const chainId = parseOptionalInteger(capRow.chainId, 'spendCap.capsByChain[].chainId');
    if (!chainId || chainId <= 0) {
      throw createError(
        'invalid_body',
        400,
        'Field spendCap.capsByChain[].chainId is required',
      );
    }
    const capMinor = parseOptionalInteger(
      capRow.capMinor,
      'spendCap.capsByChain[].capMinor',
    );
    if (capMinor === undefined) {
      throw createError(
        'invalid_body',
        400,
        'Field spendCap.capsByChain[].capMinor is required',
      );
    }
    if (seen.has(chainId)) continue;
    seen.add(chainId);
    out.push({
      chainId,
      capMinor,
    });
  }
  return {
    mode,
    period,
    capsByChain: mode === 'NONE' ? [] : out,
  };
}

function parseAllowedCalls(raw: unknown): ConsoleGasSponsorshipAllowedCall[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field allowedCalls must be an array');
  }
  const out: ConsoleGasSponsorshipAllowedCall[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw createError('invalid_body', 400, 'Field allowedCalls must contain objects');
    }
    const row = entry as Record<string, unknown>;
    const chainId = parseOptionalInteger(row.chainId, 'allowedCalls[].chainId');
    if (!chainId || chainId <= 0) {
      throw createError('invalid_body', 400, 'Field allowedCalls[].chainId is required');
    }
    const to = String(row.to || '').trim();
    if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
      throw createError('invalid_body', 400, 'Field allowedCalls[].to must be an EVM address');
    }
    const selector = String(row.selector || '').trim();
    if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) {
      throw createError(
        'invalid_body',
        400,
        'Field allowedCalls[].selector must be a 4-byte selector hex string',
      );
    }
    const dedupeKey = `${chainId}:${to.toLowerCase()}:${selector.toLowerCase()}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      chainId,
      to,
      selector: selector.toLowerCase(),
    });
  }
  return out;
}

export function parseListConsoleGasSponsorshipRequest(query: unknown): ListConsoleGasSponsorshipRequest {
  const obj = requireQueryObject(query, createError);
  return {
    ...(parseScopeType(readOptionalQueryString(obj, 'scopeType'), 'scopeType')
      ? { scopeType: parseScopeType(readOptionalQueryString(obj, 'scopeType'), 'scopeType')! }
      : {}),
    ...(readOptionalQueryString(obj, 'projectId') ? { projectId: readOptionalQueryString(obj, 'projectId') } : {}),
    ...(readOptionalQueryString(obj, 'environmentId')
      ? { environmentId: readOptionalQueryString(obj, 'environmentId') }
      : {}),
    ...(readOptionalQueryString(obj, 'policyId') ? { policyId: readOptionalQueryString(obj, 'policyId') } : {}),
    ...(readOptionalQueryString(obj, 'walletSegmentId')
      ? { walletSegmentId: readOptionalQueryString(obj, 'walletSegmentId') }
      : {}),
    ...(readOptionalQueryString(obj, 'templateId')
      ? { templateId: readOptionalQueryString(obj, 'templateId') }
      : {}),
  };
}

export function parseCreateConsoleGasSponsorshipRequest(
  body: unknown,
): CreateConsoleGasSponsorshipRequest {
  const obj = requireObject(body, createError);
  const scopeType = parseScopeType(obj.scopeType, 'scopeType');
  const networkClass = parseOptionalNetworkClass(obj.networkClass);
  const enabled = parseOptionalBoolean(obj.enabled, 'enabled');
  const allowedChainIds = parseAllowedChainIds(obj.allowedChainIds);
  const callMode = parseOptionalCallMode(obj.callMode);
  const spendCap = parseSpendCap(obj.spendCap);
  const allowedCalls = parseAllowedCalls(obj.allowedCalls);
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
    ...(readOptionalString(obj, 'policyName')
      ? { policyName: readOptionalString(obj, 'policyName') }
      : {}),
    ...(readOptionalString(obj, 'templateId')
      ? { templateId: readOptionalString(obj, 'templateId') }
      : {}),
    ...(networkClass ? { networkClass } : {}),
    ...(enabled !== undefined ? { enabled } : {}),
    ...(allowedChainIds ? { allowedChainIds } : {}),
    ...(callMode ? { callMode } : {}),
    ...(spendCap ? { spendCap } : {}),
    ...(allowedCalls ? { allowedCalls } : {}),
  };
}

export function parseUpdateConsoleGasSponsorshipRequest(
  body: unknown,
): UpdateConsoleGasSponsorshipRequest {
  const obj = requireObject(body, createError);
  const scopeType = parseScopeType(obj.scopeType, 'scopeType');
  const networkClass = parseOptionalNetworkClass(obj.networkClass);
  const enabled = parseOptionalBoolean(obj.enabled, 'enabled');
  const allowedChainIds = parseAllowedChainIds(obj.allowedChainIds);
  const callMode = parseOptionalCallMode(obj.callMode);
  const spendCap = parseSpendCap(obj.spendCap);
  const allowedCalls = parseAllowedCalls(obj.allowedCalls);
  return {
    ...(scopeType ? { scopeType } : {}),
    ...(readOptionalString(obj, 'projectId') ? { projectId: readOptionalString(obj, 'projectId') } : {}),
    ...(readOptionalString(obj, 'environmentId')
      ? { environmentId: readOptionalString(obj, 'environmentId') }
      : {}),
    ...(readOptionalString(obj, 'policyId') ? { policyId: readOptionalString(obj, 'policyId') } : {}),
    ...(readOptionalString(obj, 'walletSegmentId')
      ? { walletSegmentId: readOptionalString(obj, 'walletSegmentId') }
      : {}),
    ...(readOptionalString(obj, 'policyName')
      ? { policyName: readOptionalString(obj, 'policyName') }
      : {}),
    ...(readOptionalString(obj, 'templateId')
      ? { templateId: readOptionalString(obj, 'templateId') }
      : {}),
    ...(networkClass ? { networkClass } : {}),
    ...(enabled !== undefined ? { enabled } : {}),
    ...(allowedChainIds ? { allowedChainIds } : {}),
    ...(callMode ? { callMode } : {}),
    ...(spendCap ? { spendCap } : {}),
    ...(allowedCalls ? { allowedCalls } : {}),
  };
}

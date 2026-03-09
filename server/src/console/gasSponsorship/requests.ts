import { ConsoleGasSponsorshipError } from './errors';
import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipBudgetPeriod,
  ConsoleGasSponsorshipExecutor,
  ConsoleGasSponsorshipChainBudget,
  ConsoleGasSponsorshipFallbackBehavior,
  ConsoleGasSponsorshipNetworkClass,
  ConsoleGasSponsorshipPaymasterMode,
  ConsoleGasSponsorshipScopeType,
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
const GAS_BUDGET_PERIODS = new Set<ConsoleGasSponsorshipBudgetPeriod>(['DAILY', 'WEEKLY', 'MONTHLY']);
const GAS_PAYMASTER_MODES = new Set<ConsoleGasSponsorshipPaymasterMode>(['DISABLED', 'AUTO', 'FORCED']);
const GAS_FALLBACK_BEHAVIORS = new Set<ConsoleGasSponsorshipFallbackBehavior>([
  'REJECT',
  'ALLOW_UNSPONSORED',
]);
const GAS_NETWORK_CLASSES = new Set<ConsoleGasSponsorshipNetworkClass>([
  'ANY',
  'TESTNET',
  'MAINNET',
]);
const GAS_EXECUTORS = new Set<ConsoleGasSponsorshipExecutor>(['RELAY_EOA']);

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

function parsePeriod(raw: unknown): ConsoleGasSponsorshipBudgetPeriod {
  const value = String(raw || '')
    .trim()
    .toUpperCase() as ConsoleGasSponsorshipBudgetPeriod;
  if (!GAS_BUDGET_PERIODS.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field chainBudgets[].period must be one of: ${Array.from(GAS_BUDGET_PERIODS).join(', ')}`,
    );
  }
  return value;
}

function parsePaymasterMode(raw: unknown): ConsoleGasSponsorshipPaymasterMode | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipPaymasterMode;
  if (!GAS_PAYMASTER_MODES.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field paymasterMode must be one of: ${Array.from(GAS_PAYMASTER_MODES).join(', ')}`,
    );
  }
  return value;
}

function parseFallbackBehavior(raw: unknown): ConsoleGasSponsorshipFallbackBehavior | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipFallbackBehavior;
  if (!GAS_FALLBACK_BEHAVIORS.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field fallbackBehavior must be one of: ${Array.from(GAS_FALLBACK_BEHAVIORS).join(', ')}`,
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

function parseOptionalBigIntString(raw: unknown, field: string): string | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  try {
    const parsed = BigInt(String(raw).trim());
    if (parsed < 0n) {
      throw new Error('negative');
    }
    return parsed.toString(10);
  } catch {
    throw createError('invalid_body', 400, `Field ${field} must be a non-negative integer string`);
  }
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

function parseOptionalExecutor(raw: unknown): ConsoleGasSponsorshipExecutor | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw).trim().toUpperCase() as ConsoleGasSponsorshipExecutor;
  if (!GAS_EXECUTORS.has(value)) {
    throw createError(
      'invalid_body',
      400,
      `Field executor must be one of: ${Array.from(GAS_EXECUTORS).join(', ')}`,
    );
  }
  return value;
}

function parseChainBudgets(raw: unknown): ConsoleGasSponsorshipChainBudget[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) {
    throw createError('invalid_body', 400, 'Field chainBudgets must be an array');
  }
  const out: ConsoleGasSponsorshipChainBudget[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw createError('invalid_body', 400, 'Field chainBudgets must contain objects');
    }
    const row = entry as Record<string, unknown>;
    const chain = String(row.chain || '').trim();
    if (!chain) {
      throw createError('invalid_body', 400, 'Field chainBudgets[].chain is required');
    }
    const period = parsePeriod(row.period);
    const budgetMinor = parseOptionalInteger(row.budgetMinor, 'chainBudgets[].budgetMinor');
    const quotaTransactions = parseOptionalInteger(
      row.quotaTransactions,
      'chainBudgets[].quotaTransactions',
    );
    if (budgetMinor === undefined || quotaTransactions === undefined) {
      throw createError(
        'invalid_body',
        400,
        'Fields chainBudgets[].budgetMinor and chainBudgets[].quotaTransactions are required',
      );
    }
    const dedupeKey = `${chain.toLowerCase()}:${period}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      chain,
      period,
      budgetMinor,
      quotaTransactions,
    });
  }
  return out;
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
    const maxGasLimit = parseOptionalBigIntString(row.maxGasLimit, 'allowedCalls[].maxGasLimit');
    if (maxGasLimit === undefined) {
      throw createError('invalid_body', 400, 'Field allowedCalls[].maxGasLimit is required');
    }
    const maxValueWei = parseOptionalBigIntString(row.maxValueWei, 'allowedCalls[].maxValueWei');
    if (maxValueWei === undefined) {
      throw createError('invalid_body', 400, 'Field allowedCalls[].maxValueWei is required');
    }
    const dedupeKey = `${chainId}:${to.toLowerCase()}:${selector.toLowerCase()}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      chainId,
      to,
      selector: selector.toLowerCase(),
      maxGasLimit,
      maxValueWei,
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
    ...(parseOptionalNetworkClass(obj.networkClass)
      ? { networkClass: parseOptionalNetworkClass(obj.networkClass) }
      : {}),
    ...(parseOptionalExecutor(obj.executor)
      ? { executor: parseOptionalExecutor(obj.executor) }
      : {}),
    ...(parseOptionalBoolean(obj.enabled, 'enabled') !== undefined
      ? { enabled: parseOptionalBoolean(obj.enabled, 'enabled') }
      : {}),
    ...(parsePaymasterMode(obj.paymasterMode) ? { paymasterMode: parsePaymasterMode(obj.paymasterMode) } : {}),
    ...(parseFallbackBehavior(obj.fallbackBehavior)
      ? { fallbackBehavior: parseFallbackBehavior(obj.fallbackBehavior) }
      : {}),
    ...(parseChainBudgets(obj.chainBudgets) ? { chainBudgets: parseChainBudgets(obj.chainBudgets) } : {}),
    ...(parseAllowedCalls(obj.allowedCalls) ? { allowedCalls: parseAllowedCalls(obj.allowedCalls) } : {}),
  };
}

export function parseUpdateConsoleGasSponsorshipRequest(
  body: unknown,
): UpdateConsoleGasSponsorshipRequest {
  const obj = requireObject(body, createError);
  return {
    ...(parseScopeType(obj.scopeType, 'scopeType') ? { scopeType: parseScopeType(obj.scopeType, 'scopeType') } : {}),
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
    ...(parseOptionalNetworkClass(obj.networkClass)
      ? { networkClass: parseOptionalNetworkClass(obj.networkClass) }
      : {}),
    ...(parseOptionalExecutor(obj.executor)
      ? { executor: parseOptionalExecutor(obj.executor) }
      : {}),
    ...(parseOptionalBoolean(obj.enabled, 'enabled') !== undefined
      ? { enabled: parseOptionalBoolean(obj.enabled, 'enabled') }
      : {}),
    ...(parsePaymasterMode(obj.paymasterMode) ? { paymasterMode: parsePaymasterMode(obj.paymasterMode) } : {}),
    ...(parseFallbackBehavior(obj.fallbackBehavior)
      ? { fallbackBehavior: parseFallbackBehavior(obj.fallbackBehavior) }
      : {}),
    ...(parseChainBudgets(obj.chainBudgets) ? { chainBudgets: parseChainBudgets(obj.chainBudgets) } : {}),
    ...(parseAllowedCalls(obj.allowedCalls) ? { allowedCalls: parseAllowedCalls(obj.allowedCalls) } : {}),
  };
}

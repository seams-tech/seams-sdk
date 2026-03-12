import { ConsolePolicyError } from './errors';
import type {
  ConsoleGasSponsorshipPolicyAllowedCall,
  ConsoleGasSponsorshipPolicyCallMode,
  ConsoleGasSponsorshipPolicyNetworkClass,
  ConsoleGasSponsorshipPolicyRules,
  ConsoleGasSponsorshipPolicyRulesInput,
  ConsoleGasSponsorshipPolicyScopeType,
  ConsoleGasSponsorshipPolicySpendCap,
  ConsoleGasSponsorshipPolicySpendCapMode,
  ConsoleGasSponsorshipPolicySpendCapPeriod,
  ConsolePolicyDenyReason,
  ConsolePolicyDenyReasonCode,
  ConsolePolicyDecision,
  ConsolePolicyKind,
  ConsolePolicyRules,
  ConsolePolicyRulesInput,
  ConsoleTransactionPolicyRules,
  ConsoleTransactionPolicyRulesInput,
  SimulateConsolePolicyRequest,
  SimulateConsolePolicyNormalizedRequest,
} from './types';

export const CONSOLE_POLICY_RULE_SCHEMA_VERSION = 1 as const;

const KNOWN_TRANSACTION_RULE_KEYS = new Set([
  'schemaVersion',
  'blockedActions',
  'allowedChains',
  'maxAmountMinor',
  'allowedContractCalls',
]);
const KNOWN_GAS_RULE_KEYS = new Set([
  'schemaVersion',
  'scopeType',
  'projectId',
  'environmentId',
  'scopePolicyId',
  'walletSegmentId',
  'enabled',
  'templateId',
  'networkClass',
  'allowedChainIds',
  'callMode',
  'allowedCalls',
  'spendCap',
]);
const GAS_SCOPE_TYPES = new Set<ConsoleGasSponsorshipPolicyScopeType>([
  'ORG',
  'PROJECT',
  'ENVIRONMENT',
  'POLICY',
  'WALLET_SEGMENT',
]);
const GAS_NETWORK_CLASSES = new Set<ConsoleGasSponsorshipPolicyNetworkClass>([
  'ANY',
  'TESTNET',
  'MAINNET',
]);
const GAS_CALL_MODES = new Set<ConsoleGasSponsorshipPolicyCallMode>(['ALLOW_ALL', 'ALLOWLIST']);
const GAS_SPEND_CAP_MODES = new Set<ConsoleGasSponsorshipPolicySpendCapMode>([
  'NONE',
  'CHAIN_TOTAL',
  'WALLET_CHAIN_TOTAL',
]);
const GAS_SPEND_CAP_PERIODS = new Set<ConsoleGasSponsorshipPolicySpendCapPeriod>([
  'WEEKLY',
  'MONTHLY',
]);
const EVM_CONTRACT_ADDRESS_PATTERN = /^0x[a-fA-F0-9]{40}$/;
const EVM_FUNCTION_SELECTOR_PATTERN = /^0x[a-fA-F0-9]{8}$/;
const FUNCTION_SIGNATURE_PATTERN = /^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)$/;
const FUNCTION_SIGNATURE_PARAM_PATTERN = /^[A-Za-z0-9_$.[\]]+$/;

type ParseMode = 'request' | 'storage';

interface EvaluationResult {
  decision: ConsolePolicyDecision;
  denyReasons: ConsolePolicyDenyReason[];
  normalizedRequest: SimulateConsolePolicyNormalizedRequest;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function invalidRulesError(message: string): ConsolePolicyError {
  return new ConsolePolicyError('invalid_body', 400, message);
}

function dedupeCaseInsensitive(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of values) {
    const normalized = entry.toLowerCase();
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(entry);
  }
  return out;
}

function dedupeExact(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of values) {
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
  }
  return out;
}

function readOptionalTrimmedString(value: unknown): string | null {
  const out = String(value || '').trim();
  return out || null;
}

function readStringListField(
  obj: Record<string, unknown>,
  key: 'blockedActions' | 'allowedChains',
  mode: ParseMode,
): string[] {
  const raw = obj[key];
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    if (mode === 'request') {
      throw invalidRulesError(`Policy rule ${key} must be an array of strings`);
    }
    return [];
  }
  const out: string[] = [];
  for (const entry of raw) {
    if (typeof entry !== 'string') {
      if (mode === 'request') {
        throw invalidRulesError(`Policy rule ${key} must contain only strings`);
      }
      continue;
    }
    const value = entry.trim();
    if (!value) {
      if (mode === 'request') {
        throw invalidRulesError(`Policy rule ${key} may not contain empty strings`);
      }
      continue;
    }
    out.push(value);
  }
  return dedupeCaseInsensitive(out);
}

export function normalizeConsolePolicyContractAddress(value: unknown): string | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!normalized) return null;
  if (!EVM_CONTRACT_ADDRESS_PATTERN.test(normalized)) return null;
  return normalized;
}

export function normalizeConsolePolicyFunctionIdentifier(value: unknown): string | null {
  const normalized = String(value || '').trim();
  if (!normalized) return null;
  if (EVM_FUNCTION_SELECTOR_PATTERN.test(normalized)) {
    return normalized.toLowerCase();
  }
  const signatureMatch = normalized.match(FUNCTION_SIGNATURE_PATTERN);
  if (!signatureMatch) return null;
  const functionName = String(signatureMatch[1] || '').trim();
  const rawParamList = String(signatureMatch[2] || '').trim();
  if (!functionName) return null;
  if (!rawParamList) return `${functionName}()`;
  const params = rawParamList.split(',').map((entry) => entry.trim());
  if (params.length === 0 || params.some((entry) => !entry)) return null;
  if (params.some((entry) => !FUNCTION_SIGNATURE_PARAM_PATTERN.test(entry))) return null;
  return `${functionName}(${params.join(',')})`;
}

function readContractCallRules(
  obj: Record<string, unknown>,
  mode: ParseMode,
): ConsoleTransactionPolicyRules['allowedContractCalls'] {
  const raw = obj.allowedContractCalls;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule allowedContractCalls must be an array');
    }
    return [];
  }
  const out: ConsoleTransactionPolicyRules['allowedContractCalls'] = [];
  const seenContracts = new Set<string>();
  for (const entry of raw) {
    if (!isObjectRecord(entry)) {
      if (mode === 'request') {
        throw invalidRulesError('Policy rule allowedContractCalls entries must be objects');
      }
      continue;
    }
    const contractAddress = normalizeConsolePolicyContractAddress(entry.contractAddress);
    if (!contractAddress) {
      if (mode === 'request') {
        throw invalidRulesError(
          'Policy rule allowedContractCalls contractAddress must be a 20-byte hex address',
        );
      }
      continue;
    }
    if (seenContracts.has(contractAddress)) {
      if (mode === 'request') {
        throw invalidRulesError(
          `Policy rule allowedContractCalls may not repeat contractAddress ${contractAddress}`,
        );
      }
      continue;
    }
    seenContracts.add(contractAddress);
    const functionsRaw = entry.functions;
    const functions =
      functionsRaw === undefined || functionsRaw === null
        ? []
        : (() => {
            if (!Array.isArray(functionsRaw)) {
              if (mode === 'request') {
                throw invalidRulesError(
                  'Policy rule allowedContractCalls functions must be an array of strings',
                );
              }
              return [];
            }
            const values: string[] = [];
            const seenFunctions = new Set<string>();
            for (const functionEntry of functionsRaw) {
              const normalized = normalizeConsolePolicyFunctionIdentifier(functionEntry);
              if (!normalized) {
                if (mode === 'request') {
                  throw invalidRulesError(
                    'Policy rule allowedContractCalls functions must be 4-byte selectors or function signatures',
                  );
                }
                continue;
              }
              if (seenFunctions.has(normalized)) {
                if (mode === 'request') {
                  throw invalidRulesError(
                    `Policy rule allowedContractCalls functions may not repeat ${normalized}`,
                  );
                }
                continue;
              }
              seenFunctions.add(normalized);
              values.push(normalized);
            }
            return dedupeExact(values);
          })();
    out.push({
      contractAddress,
      functions,
    });
  }
  return out;
}

function readSchemaVersion(
  obj: Record<string, unknown>,
  mode: ParseMode,
): typeof CONSOLE_POLICY_RULE_SCHEMA_VERSION {
  const raw = obj.schemaVersion;
  if (raw === undefined || raw === null || raw === '') {
    return CONSOLE_POLICY_RULE_SCHEMA_VERSION;
  }
  const version = typeof raw === 'number' ? raw : Number(raw);
  if (version !== CONSOLE_POLICY_RULE_SCHEMA_VERSION) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule schemaVersion must be ${CONSOLE_POLICY_RULE_SCHEMA_VERSION}`,
      );
    }
    return CONSOLE_POLICY_RULE_SCHEMA_VERSION;
  }
  return CONSOLE_POLICY_RULE_SCHEMA_VERSION;
}

function readOptionalNonNegativeInteger(
  obj: Record<string, unknown>,
  key: 'maxAmountMinor',
  mode: ParseMode,
): number | undefined {
  const raw = obj[key];
  if (raw === undefined || raw === null || raw === '') return undefined;
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    if (mode === 'request') {
      throw invalidRulesError(`Policy rule ${key} must be a non-negative integer`);
    }
    return undefined;
  }
  return value;
}

function parseTransactionPolicyRules(raw: unknown, mode: ParseMode): ConsoleTransactionPolicyRules {
  if (raw === undefined || raw === null) return createDefaultConsolePolicyRules();
  if (!isObjectRecord(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Field rules must be a JSON object');
    }
    return createDefaultConsolePolicyRules();
  }

  if (mode === 'request') {
    for (const key of Object.keys(raw)) {
      if (!KNOWN_TRANSACTION_RULE_KEYS.has(key)) {
        throw invalidRulesError(`Unknown policy rule key ${key}`);
      }
    }
  }

  const schemaVersion = readSchemaVersion(raw, mode);
  const blockedActions = readStringListField(raw, 'blockedActions', mode);
  const allowedChains = readStringListField(raw, 'allowedChains', mode);
  const maxAmountMinor = readOptionalNonNegativeInteger(raw, 'maxAmountMinor', mode);
  const allowedContractCalls = readContractCallRules(raw, mode);

  return {
    schemaVersion,
    blockedActions,
    allowedChains,
    allowedContractCalls,
    ...(maxAmountMinor !== undefined ? { maxAmountMinor } : {}),
  };
}

function readOptionalGasScopeType(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicyScopeType | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw || '').trim().toUpperCase() as ConsoleGasSponsorshipPolicyScopeType;
  if (!GAS_SCOPE_TYPES.has(value)) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule scopeType must be one of ${Array.from(GAS_SCOPE_TYPES).join(', ')}`,
      );
    }
    return undefined;
  }
  return value;
}

function readOptionalGasBoolean(raw: unknown, key: string, mode: ParseMode): boolean | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw === 'boolean') return raw;
  const normalized = String(raw || '').trim().toLowerCase();
  if (normalized === 'true' || normalized === '1') return true;
  if (normalized === 'false' || normalized === '0') return false;
  if (mode === 'request') {
    throw invalidRulesError(`Policy rule ${key} must be a boolean`);
  }
  return undefined;
}

function readOptionalPositiveInteger(raw: unknown, key: string, mode: ParseMode): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    if (mode === 'request') {
      throw invalidRulesError(`Policy rule ${key} must be a positive integer`);
    }
    return undefined;
  }
  return value;
}

function readOptionalGasNetworkClass(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicyNetworkClass | undefined {
  if (raw === undefined || raw === null || String(raw).trim() === '') return undefined;
  const value = String(raw || '').trim().toUpperCase() as ConsoleGasSponsorshipPolicyNetworkClass;
  if (!GAS_NETWORK_CLASSES.has(value)) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule networkClass must be one of ${Array.from(GAS_NETWORK_CLASSES).join(', ')}`,
      );
    }
    return undefined;
  }
  return value;
}

function readGasAllowedChainIds(raw: unknown, mode: ParseMode): number[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule allowedChainIds must be an array');
    }
    return [];
  }
  const out: number[] = [];
  const seen = new Set<number>();
  for (const entry of raw) {
    const chainId = readOptionalPositiveInteger(entry, 'allowedChainIds[]', mode);
    if (!chainId) continue;
    if (seen.has(chainId)) continue;
    seen.add(chainId);
    out.push(chainId);
  }
  return out;
}

function normalizeGasAllowedCallSelector(value: unknown): string | null {
  const normalized = String(value || '').trim();
  if (!normalized) return null;
  return EVM_FUNCTION_SELECTOR_PATTERN.test(normalized) ? normalized.toLowerCase() : null;
}

function readGasAllowedCalls(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicyAllowedCall[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule allowedCalls must be an array');
    }
    return [];
  }
  const out: ConsoleGasSponsorshipPolicyAllowedCall[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    if (!isObjectRecord(entry)) {
      if (mode === 'request') {
        throw invalidRulesError('Policy rule allowedCalls entries must be objects');
      }
      continue;
    }
    const chainId = readOptionalPositiveInteger(entry.chainId, 'allowedCalls[].chainId', mode);
    const to = normalizeConsolePolicyContractAddress(entry.to);
    const selector = normalizeGasAllowedCallSelector(entry.selector);
    if (!chainId || !to || !selector) {
      if (mode === 'request') {
        if (!chainId) {
          throw invalidRulesError('Policy rule allowedCalls[].chainId must be a positive integer');
        }
        if (!to) {
          throw invalidRulesError('Policy rule allowedCalls[].to must be an EVM address');
        }
        throw invalidRulesError(
          'Policy rule allowedCalls[].selector must be a 4-byte selector hex string',
        );
      }
      continue;
    }
    const dedupeKey = `${chainId}:${to}:${selector}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({ chainId, to, selector });
  }
  return out;
}

function readGasCallMode(
  raw: unknown,
  mode: ParseMode,
  allowedCalls: ConsoleGasSponsorshipPolicyAllowedCall[],
): ConsoleGasSponsorshipPolicyCallMode {
  if (raw === undefined || raw === null || String(raw).trim() === '') {
    return allowedCalls.length > 0 ? 'ALLOWLIST' : 'ALLOW_ALL';
  }
  const value = String(raw || '').trim().toUpperCase() as ConsoleGasSponsorshipPolicyCallMode;
  if (!GAS_CALL_MODES.has(value)) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule callMode must be one of ${Array.from(GAS_CALL_MODES).join(', ')}`,
      );
    }
    return allowedCalls.length > 0 ? 'ALLOWLIST' : 'ALLOW_ALL';
  }
  return value;
}

function readGasSpendCapMode(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicySpendCapMode {
  if (raw === undefined || raw === null || raw === '') return 'NONE';
  const value = String(raw || '').trim().toUpperCase() as ConsoleGasSponsorshipPolicySpendCapMode;
  if (!GAS_SPEND_CAP_MODES.has(value)) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule spendCap.mode must be one of ${Array.from(GAS_SPEND_CAP_MODES).join(', ')}`,
      );
    }
    return 'NONE';
  }
  return value;
}

function readGasSpendCapPeriod(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicySpendCapPeriod {
  if (raw === undefined || raw === null || raw === '') return 'MONTHLY';
  const value = String(raw || '')
    .trim()
    .toUpperCase() as ConsoleGasSponsorshipPolicySpendCapPeriod;
  if (!GAS_SPEND_CAP_PERIODS.has(value)) {
    if (mode === 'request') {
      throw invalidRulesError(
        `Policy rule spendCap.period must be one of ${Array.from(GAS_SPEND_CAP_PERIODS).join(', ')}`,
      );
    }
    return 'MONTHLY';
  }
  return value;
}

function readGasSpendCap(raw: unknown, mode: ParseMode): ConsoleGasSponsorshipPolicySpendCap {
  if (raw === undefined || raw === null) {
    return {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    };
  }
  if (!isObjectRecord(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule spendCap must be a JSON object');
    }
    return {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    };
  }
  const modeValue = readGasSpendCapMode(raw.mode, mode);
  const capsRaw = raw.capsByChain;
  if (capsRaw !== undefined && capsRaw !== null && !Array.isArray(capsRaw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule spendCap.capsByChain must be an array');
    }
  }
  const out: ConsoleGasSponsorshipPolicySpendCap['capsByChain'] = [];
  const seen = new Set<number>();
  for (const entry of Array.isArray(capsRaw) ? capsRaw : []) {
    if (!isObjectRecord(entry)) {
      if (mode === 'request') {
        throw invalidRulesError('Policy rule spendCap.capsByChain entries must be objects');
      }
      continue;
    }
    const chainId = readOptionalPositiveInteger(
      entry.chainId,
      'spendCap.capsByChain[].chainId',
      mode,
    );
    const capMinor = readOptionalPositiveInteger(
      entry.capMinor,
      'spendCap.capsByChain[].capMinor',
      mode,
    );
    if (!chainId || capMinor === undefined) {
      if (mode === 'request') {
        if (!chainId) {
          throw invalidRulesError(
            'Policy rule spendCap.capsByChain[].chainId must be a positive integer',
          );
        }
        throw invalidRulesError(
          'Policy rule spendCap.capsByChain[].capMinor must be a positive integer',
        );
      }
      continue;
    }
    if (seen.has(chainId)) continue;
    seen.add(chainId);
    out.push({ chainId, capMinor });
  }
  return {
    mode: modeValue,
    period: readGasSpendCapPeriod(raw.period, mode),
    capsByChain: modeValue === 'NONE' ? [] : out,
  };
}

function parseGasSponsorshipPolicyRules(
  raw: unknown,
  mode: ParseMode,
): ConsoleGasSponsorshipPolicyRules {
  if (raw === undefined || raw === null) {
    return createDefaultConsolePolicyRules('GAS_SPONSORSHIP');
  }
  if (!isObjectRecord(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Field rules must be a JSON object');
    }
    return createDefaultConsolePolicyRules('GAS_SPONSORSHIP');
  }

  if (mode === 'request') {
    for (const key of Object.keys(raw)) {
      if (!KNOWN_GAS_RULE_KEYS.has(key)) {
        throw invalidRulesError(`Unknown policy rule key ${key}`);
      }
    }
  }

  const schemaVersion = readSchemaVersion(raw, mode);
  const allowedCalls = readGasAllowedCalls(raw.allowedCalls, mode);
  const callMode = readGasCallMode(raw.callMode, mode, allowedCalls);
  const spendCap = readGasSpendCap(raw.spendCap, mode);

  return {
    schemaVersion,
    scopeType: readOptionalGasScopeType(raw.scopeType, mode) || 'ORG',
    projectId: readOptionalTrimmedString(raw.projectId),
    environmentId: readOptionalTrimmedString(raw.environmentId),
    scopePolicyId: readOptionalTrimmedString(raw.scopePolicyId),
    walletSegmentId: readOptionalTrimmedString(raw.walletSegmentId),
    enabled: readOptionalGasBoolean(raw.enabled, 'enabled', mode) ?? true,
    templateId: readOptionalTrimmedString(raw.templateId),
    networkClass: readOptionalGasNetworkClass(raw.networkClass, mode) || 'ANY',
    allowedChainIds: readGasAllowedChainIds(raw.allowedChainIds, mode),
    callMode,
    allowedCalls: callMode === 'ALLOW_ALL' ? [] : allowedCalls,
    spendCap,
  };
}

export function createDefaultConsolePolicyRules(): ConsoleTransactionPolicyRules;
export function createDefaultConsolePolicyRules(
  kind: 'TRANSACTION',
): ConsoleTransactionPolicyRules;
export function createDefaultConsolePolicyRules(
  kind: 'GAS_SPONSORSHIP',
): ConsoleGasSponsorshipPolicyRules;
export function createDefaultConsolePolicyRules(
  kind: ConsolePolicyKind = 'TRANSACTION',
): ConsolePolicyRules {
  if (kind === 'GAS_SPONSORSHIP') {
    return {
      schemaVersion: CONSOLE_POLICY_RULE_SCHEMA_VERSION,
      scopeType: 'ORG',
      projectId: null,
      environmentId: null,
      scopePolicyId: null,
      walletSegmentId: null,
      enabled: true,
      templateId: null,
      networkClass: 'ANY',
      allowedChainIds: [],
      callMode: 'ALLOW_ALL',
      allowedCalls: [],
      spendCap: {
        mode: 'NONE',
        period: 'MONTHLY',
        capsByChain: [],
      },
    };
  }
  return {
    schemaVersion: CONSOLE_POLICY_RULE_SCHEMA_VERSION,
    blockedActions: [],
    allowedChains: [],
    allowedContractCalls: [],
  };
}

export function isConsoleGasSponsorshipPolicyRules(
  rules: ConsolePolicyRules,
): rules is ConsoleGasSponsorshipPolicyRules {
  return Object.prototype.hasOwnProperty.call(rules, 'scopeType');
}

export function isConsoleTransactionPolicyRules(
  rules: ConsolePolicyRules,
): rules is ConsoleTransactionPolicyRules {
  return !isConsoleGasSponsorshipPolicyRules(rules);
}

export function cloneConsolePolicyRules(rules: ConsolePolicyRules): ConsolePolicyRules {
  if (isConsoleGasSponsorshipPolicyRules(rules)) {
    return {
      schemaVersion: rules.schemaVersion,
      scopeType: rules.scopeType,
      projectId: rules.projectId,
      environmentId: rules.environmentId,
      scopePolicyId: rules.scopePolicyId,
      walletSegmentId: rules.walletSegmentId,
      enabled: rules.enabled,
      templateId: rules.templateId,
      networkClass: rules.networkClass,
      allowedChainIds: [...rules.allowedChainIds],
      callMode: rules.callMode,
      allowedCalls: rules.allowedCalls.map((entry) => ({
        chainId: entry.chainId,
        to: entry.to,
        selector: entry.selector,
      })),
      spendCap: {
        mode: rules.spendCap.mode,
        period: rules.spendCap.period,
        capsByChain: rules.spendCap.capsByChain.map((entry) => ({
          chainId: entry.chainId,
          capMinor: entry.capMinor,
        })),
      },
    };
  }
  return {
    schemaVersion: rules.schemaVersion,
    blockedActions: [...rules.blockedActions],
    allowedChains: [...rules.allowedChains],
    allowedContractCalls: rules.allowedContractCalls.map((entry) => ({
      contractAddress: entry.contractAddress,
      functions: [...entry.functions],
    })),
    ...(rules.maxAmountMinor !== undefined ? { maxAmountMinor: rules.maxAmountMinor } : {}),
  };
}

export function parseConsolePolicyRulesInput(
  raw: ConsoleTransactionPolicyRulesInput | unknown,
): ConsoleTransactionPolicyRules;
export function parseConsolePolicyRulesInput(
  raw: ConsolePolicyRulesInput | unknown,
  kind: 'TRANSACTION',
): ConsoleTransactionPolicyRules;
export function parseConsolePolicyRulesInput(
  raw: ConsolePolicyRulesInput | unknown,
  kind: 'GAS_SPONSORSHIP',
): ConsoleGasSponsorshipPolicyRules;
export function parseConsolePolicyRulesInput(
  raw: ConsolePolicyRulesInput | unknown,
  kind: ConsolePolicyKind,
): ConsolePolicyRules;
export function parseConsolePolicyRulesInput(
  raw: ConsolePolicyRulesInput | unknown,
  kind: ConsolePolicyKind = 'TRANSACTION',
): ConsolePolicyRules {
  return kind === 'GAS_SPONSORSHIP'
    ? parseGasSponsorshipPolicyRules(raw, 'request')
    : parseTransactionPolicyRules(raw, 'request');
}

export function parseStoredConsolePolicyRules(raw: unknown): ConsoleTransactionPolicyRules;
export function parseStoredConsolePolicyRules(
  raw: unknown,
  kind: 'TRANSACTION',
): ConsoleTransactionPolicyRules;
export function parseStoredConsolePolicyRules(
  raw: unknown,
  kind: 'GAS_SPONSORSHIP',
): ConsoleGasSponsorshipPolicyRules;
export function parseStoredConsolePolicyRules(
  raw: unknown,
  kind: ConsolePolicyKind,
): ConsolePolicyRules;
export function parseStoredConsolePolicyRules(
  raw: unknown,
  kind: ConsolePolicyKind = 'TRANSACTION',
): ConsolePolicyRules {
  return kind === 'GAS_SPONSORSHIP'
    ? parseGasSponsorshipPolicyRules(raw, 'storage')
    : parseTransactionPolicyRules(raw, 'storage');
}

export function serializeConsolePolicyRules(rules: ConsolePolicyRules): Record<string, unknown> {
  if (isConsoleGasSponsorshipPolicyRules(rules)) {
    return {
      schemaVersion: rules.schemaVersion,
      scopeType: rules.scopeType,
      projectId: rules.projectId,
      environmentId: rules.environmentId,
      scopePolicyId: rules.scopePolicyId,
      walletSegmentId: rules.walletSegmentId,
      enabled: rules.enabled,
      templateId: rules.templateId,
      networkClass: rules.networkClass,
      allowedChainIds: [...rules.allowedChainIds],
      callMode: rules.callMode,
      allowedCalls: rules.allowedCalls.map((entry) => ({
        chainId: entry.chainId,
        to: entry.to,
        selector: entry.selector,
      })),
      spendCap: {
        mode: rules.spendCap.mode,
        period: rules.spendCap.period,
        capsByChain: rules.spendCap.capsByChain.map((entry) => ({
          chainId: entry.chainId,
          capMinor: entry.capMinor,
        })),
      },
    };
  }
  return {
    schemaVersion: rules.schemaVersion,
    blockedActions: [...rules.blockedActions],
    allowedChains: [...rules.allowedChains],
    allowedContractCalls: rules.allowedContractCalls.map((entry) => ({
      contractAddress: entry.contractAddress,
      functions: [...entry.functions],
    })),
    ...(rules.maxAmountMinor !== undefined ? { maxAmountMinor: rules.maxAmountMinor } : {}),
  };
}

export function validateGasSponsorshipPolicyRulesForPublish(
  rules: ConsoleGasSponsorshipPolicyRules,
): void {
  if (rules.scopeType === 'PROJECT' && !rules.projectId) {
    throw invalidRulesError('Gas sponsorship policy scope PROJECT requires projectId');
  }
  if (rules.scopeType === 'ENVIRONMENT' && !rules.environmentId) {
    throw invalidRulesError('Gas sponsorship policy scope ENVIRONMENT requires environmentId');
  }
  if (rules.scopeType === 'POLICY' && !rules.scopePolicyId) {
    throw invalidRulesError('Gas sponsorship policy scope POLICY requires scopePolicyId');
  }
  if (rules.scopeType === 'WALLET_SEGMENT' && !rules.walletSegmentId) {
    throw invalidRulesError('Gas sponsorship policy scope WALLET_SEGMENT requires walletSegmentId');
  }
  if (rules.allowedChainIds.length === 0) {
    throw invalidRulesError('Gas sponsorship policy must include at least one allowedChainId');
  }
  if (rules.callMode === 'ALLOWLIST' && rules.allowedCalls.length === 0) {
    throw invalidRulesError('Gas sponsorship policy ALLOWLIST mode requires at least one allowedCall');
  }
  const allowedChainIds = new Set(rules.allowedChainIds);
  const invalidAllowedCall = rules.allowedCalls.find((entry) => !allowedChainIds.has(entry.chainId));
  if (invalidAllowedCall) {
    throw invalidRulesError(
      `Gas sponsorship allowed call chain ${invalidAllowedCall.chainId} is not included in allowedChainIds`,
    );
  }
  if (rules.spendCap.mode === 'NONE') return;
  const invalidSpendCap = rules.spendCap.capsByChain.find(
    (entry) => !allowedChainIds.has(entry.chainId),
  );
  if (invalidSpendCap) {
    throw invalidRulesError(
      `Gas sponsorship spend cap chain ${invalidSpendCap.chainId} is not included in allowedChainIds`,
    );
  }
}

export function normalizeConsolePolicyActionIdentifier(value: unknown): string {
  return String(value || '')
    .trim()
    .toLowerCase();
}

export function normalizeConsolePolicyChainIdentifier(value: unknown): string | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized || null;
}

function makeDenyReason(code: ConsolePolicyDenyReasonCode, message: string): ConsolePolicyDenyReason {
  return { code, message };
}

export function evaluateConsolePolicyRules(
  rules: ConsoleTransactionPolicyRules,
  request: SimulateConsolePolicyRequest,
): EvaluationResult {
  const normalizedRequest: SimulateConsolePolicyNormalizedRequest = {
    action: normalizeConsolePolicyActionIdentifier(request.action),
    chain: normalizeConsolePolicyChainIdentifier(request.chain),
    amountMinor:
      typeof request.amountMinor === 'number' && Number.isFinite(request.amountMinor)
        ? request.amountMinor
        : null,
    contractAddress: normalizeConsolePolicyContractAddress(request.contractAddress),
    functionSelector: normalizeConsolePolicyFunctionIdentifier(request.functionSelector),
  };
  const action = normalizedRequest.action;
  const blockedActions = new Set(rules.blockedActions.map((entry) => entry.toLowerCase()));
  if (action && blockedActions.has(action)) {
    return {
      decision: 'DENY',
      denyReasons: [
        makeDenyReason(
          'ACTION_BLOCKED',
          `Action ${String(request.action || '').trim() || action} is blocked by policy`,
        ),
      ],
      normalizedRequest,
    };
  }

  const chain = normalizedRequest.chain;
  if (rules.allowedChains.length > 0 && chain) {
    const allowedChains = new Set(rules.allowedChains.map((entry) => entry.toLowerCase()));
    if (!allowedChains.has(chain)) {
      return {
        decision: 'DENY',
        denyReasons: [makeDenyReason('CHAIN_NOT_ALLOWED', `Chain ${chain} is not allowed by policy`)],
        normalizedRequest,
      };
    }
  }

  if (rules.maxAmountMinor !== undefined && request.amountMinor !== undefined) {
    if (request.amountMinor > rules.maxAmountMinor) {
      return {
        decision: 'DENY',
        denyReasons: [
          makeDenyReason(
            'AMOUNT_LIMIT_EXCEEDED',
            `Amount ${request.amountMinor} exceeds maxAmountMinor ${rules.maxAmountMinor}`,
          ),
        ],
        normalizedRequest,
      };
    }
  }

  if (action === 'contract_call' && rules.allowedContractCalls.length > 0) {
    const contractAddress = normalizedRequest.contractAddress;
    const target = contractAddress
      ? rules.allowedContractCalls.find((entry) => entry.contractAddress === contractAddress) || null
      : null;
    if (!target) {
      return {
        decision: 'DENY',
        denyReasons: [
          makeDenyReason(
            'CONTRACT_NOT_ALLOWED',
            contractAddress
              ? `Contract ${contractAddress} is not allowed by policy`
              : 'Contract address is required for contract_call evaluation',
          ),
        ],
        normalizedRequest,
      };
    }
    if (target.functions.length > 0) {
      const functionSelector = normalizedRequest.functionSelector;
      if (!functionSelector || !target.functions.includes(functionSelector)) {
        return {
          decision: 'DENY',
          denyReasons: [
            makeDenyReason(
              'FUNCTION_NOT_ALLOWED',
              functionSelector
                ? `Function ${functionSelector} is not allowed for contract ${target.contractAddress}`
                : `Function selector is required for contract ${target.contractAddress}`,
            ),
          ],
          normalizedRequest,
        };
      }
    }
  }

  return {
    decision: 'ALLOW',
    denyReasons: [],
    normalizedRequest,
  };
}

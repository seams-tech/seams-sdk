import { ConsolePolicyError } from './errors';
import type {
  ConsolePolicyDenyReason,
  ConsolePolicyDenyReasonCode,
  ConsolePolicyDecision,
  ConsolePolicyRules,
  ConsolePolicyRulesInput,
  SimulateConsolePolicyRequest,
  SimulateConsolePolicyNormalizedRequest,
} from './types';

export const CONSOLE_POLICY_RULE_SCHEMA_VERSION = 1 as const;

const KNOWN_RULE_KEYS = new Set([
  'schemaVersion',
  'blockedActions',
  'allowedChains',
  'maxAmountMinor',
  'allowedContractCalls',
]);

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

function normalizeContractAddress(value: unknown): string | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized || null;
}

function normalizeFunctionSelector(value: unknown): string | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized || null;
}

function readContractCallRules(
  obj: Record<string, unknown>,
  mode: ParseMode,
): ConsolePolicyRules['allowedContractCalls'] {
  const raw = obj.allowedContractCalls;
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Policy rule allowedContractCalls must be an array');
    }
    return [];
  }
  const out: ConsolePolicyRules['allowedContractCalls'] = [];
  const seenContracts = new Set<string>();
  for (const entry of raw) {
    if (!isObjectRecord(entry)) {
      if (mode === 'request') {
        throw invalidRulesError('Policy rule allowedContractCalls entries must be objects');
      }
      continue;
    }
    const contractAddress = normalizeContractAddress(entry.contractAddress);
    if (!contractAddress) {
      if (mode === 'request') {
        throw invalidRulesError(
          'Policy rule allowedContractCalls entries require contractAddress',
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
            for (const functionEntry of functionsRaw) {
              const normalized = normalizeFunctionSelector(functionEntry);
              if (!normalized) {
                if (mode === 'request') {
                  throw invalidRulesError(
                    'Policy rule allowedContractCalls functions may not contain empty values',
                  );
                }
                continue;
              }
              values.push(normalized);
            }
            return dedupeCaseInsensitive(values);
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

function parseConsolePolicyRules(raw: unknown, mode: ParseMode): ConsolePolicyRules {
  if (raw === undefined || raw === null) return createDefaultConsolePolicyRules();
  if (!isObjectRecord(raw)) {
    if (mode === 'request') {
      throw invalidRulesError('Field rules must be a JSON object');
    }
    return createDefaultConsolePolicyRules();
  }

  if (mode === 'request') {
    for (const key of Object.keys(raw)) {
      if (!KNOWN_RULE_KEYS.has(key)) {
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

export function createDefaultConsolePolicyRules(): ConsolePolicyRules {
  return {
    schemaVersion: CONSOLE_POLICY_RULE_SCHEMA_VERSION,
    blockedActions: [],
    allowedChains: [],
    allowedContractCalls: [],
  };
}

export function cloneConsolePolicyRules(rules: ConsolePolicyRules): ConsolePolicyRules {
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

export function parseConsolePolicyRulesInput(raw: ConsolePolicyRulesInput | unknown): ConsolePolicyRules {
  return parseConsolePolicyRules(raw, 'request');
}

export function parseStoredConsolePolicyRules(raw: unknown): ConsolePolicyRules {
  return parseConsolePolicyRules(raw, 'storage');
}

export function serializeConsolePolicyRules(rules: ConsolePolicyRules): Record<string, unknown> {
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
  rules: ConsolePolicyRules,
  request: SimulateConsolePolicyRequest,
): EvaluationResult {
  const normalizedRequest: SimulateConsolePolicyNormalizedRequest = {
    action: normalizeConsolePolicyActionIdentifier(request.action),
    chain: normalizeConsolePolicyChainIdentifier(request.chain),
    amountMinor:
      typeof request.amountMinor === 'number' && Number.isFinite(request.amountMinor)
        ? request.amountMinor
        : null,
    contractAddress: normalizeContractAddress(request.contractAddress),
    functionSelector: normalizeFunctionSelector(request.functionSelector),
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

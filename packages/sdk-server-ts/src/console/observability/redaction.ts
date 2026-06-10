import type { ConsoleObservabilityMetadataRedactionPolicy } from './types';

const DEFAULT_DENYLIST_KEYS = [
  'authorization',
  'token',
  'secret',
  'password',
  'api_key',
  'apikey',
  'private_key',
  'cookie',
  'signature',
] as const;

const DEFAULT_MAX_DEPTH = 6;
const DEFAULT_MAX_STRING_LENGTH = 4096;
const DEFAULT_REPLACEMENT = '[REDACTED]';
const DEFAULT_REDACTION_VERSION = 1;

export interface ConsoleObservabilityRedactionResult {
  metadata: Record<string, unknown>;
  redactionApplied: boolean;
  redactionVersion: number;
}

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function normalizeKey(raw: string): string {
  return normalizeString(raw)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_');
}

function toPolicy(input?: ConsoleObservabilityMetadataRedactionPolicy): Required<
  Pick<
    ConsoleObservabilityMetadataRedactionPolicy,
    'denylistKeys' | 'allowlistKeys' | 'maxDepth' | 'maxStringLength' | 'replacement' | 'redactionVersion'
  >
> {
  const denylistKeys = Array.from(
    new Set(
      (input?.denylistKeys && input.denylistKeys.length > 0
        ? input.denylistKeys
        : [...DEFAULT_DENYLIST_KEYS]
      ).map((entry) => normalizeKey(entry)),
    ),
  );
  const allowlistKeys = Array.from(
    new Set((input?.allowlistKeys || []).map((entry) => normalizeKey(entry))),
  );
  const maxDepth = Number.isFinite(Number(input?.maxDepth))
    ? Math.max(1, Math.floor(Number(input?.maxDepth)))
    : DEFAULT_MAX_DEPTH;
  const maxStringLength = Number.isFinite(Number(input?.maxStringLength))
    ? Math.max(8, Math.floor(Number(input?.maxStringLength)))
    : DEFAULT_MAX_STRING_LENGTH;
  const replacement = normalizeString(input?.replacement) || DEFAULT_REPLACEMENT;
  const redactionVersion = Number.isFinite(Number(input?.redactionVersion))
    ? Math.max(1, Math.floor(Number(input?.redactionVersion)))
    : DEFAULT_REDACTION_VERSION;
  return {
    denylistKeys,
    allowlistKeys,
    maxDepth,
    maxStringLength,
    replacement,
    redactionVersion,
  };
}

function shouldRedactKey(
  key: string,
  policy: ReturnType<typeof toPolicy>,
): boolean {
  const normalized = normalizeKey(key);
  if (!normalized) return false;
  if (policy.allowlistKeys.includes(normalized)) return false;
  return policy.denylistKeys.some((deny) => normalized.includes(deny));
}

function truncateString(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  return value.slice(0, Math.max(0, maxLength - 1)) + '…';
}

function sanitizeValue(
  value: unknown,
  input: {
    keyPath: string[];
    depth: number;
    policy: ReturnType<typeof toPolicy>;
    state: { redactionApplied: boolean };
  },
): unknown {
  const { keyPath, depth, policy, state } = input;
  if (depth > policy.maxDepth) {
    state.redactionApplied = true;
    return policy.replacement;
  }

  const key = keyPath[keyPath.length - 1] || '';
  if (key && shouldRedactKey(key, policy)) {
    state.redactionApplied = true;
    return policy.replacement;
  }

  if (value === null || value === undefined) return null;
  if (typeof value === 'string') {
    return truncateString(value, policy.maxStringLength);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }

  if (Array.isArray(value)) {
    return value.map((entry, index) =>
      sanitizeValue(entry, {
        keyPath: [...keyPath, String(index)],
        depth: depth + 1,
        policy,
        state,
      }),
    );
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [entryKey, entryValue] of Object.entries(value as Record<string, unknown>)) {
      out[entryKey] = sanitizeValue(entryValue, {
        keyPath: [...keyPath, entryKey],
        depth: depth + 1,
        policy,
        state,
      });
    }
    return out;
  }

  return truncateString(String(value), policy.maxStringLength);
}

export function redactConsoleObservabilityMetadata(
  metadata: Record<string, unknown> | undefined,
  policyInput?: ConsoleObservabilityMetadataRedactionPolicy,
): ConsoleObservabilityRedactionResult {
  const policy = toPolicy(policyInput);
  const state = { redactionApplied: false };
  const source =
    metadata && typeof metadata === 'object' && !Array.isArray(metadata) ? metadata : {};
  const sanitized = sanitizeValue(source, {
    keyPath: [],
    depth: 0,
    policy,
    state,
  });
  return {
    metadata:
      sanitized && typeof sanitized === 'object' && !Array.isArray(sanitized)
        ? (sanitized as Record<string, unknown>)
        : {},
    redactionApplied: state.redactionApplied,
    redactionVersion: policy.redactionVersion,
  };
}

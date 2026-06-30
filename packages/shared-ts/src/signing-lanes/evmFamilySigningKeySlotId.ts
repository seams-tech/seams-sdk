import { parseWalletKeyId } from './ids';
import type { DomainIdParseResult } from '../utils/domainIds';

export type EvmFamilySigningKeySlotId = string & {
  readonly __evmFamilySigningKeySlotIdBrand: 'EvmFamilySigningKeySlotId';
};

function requiredPart(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new Error(`EVM-family signing key slot id requires ${field}`);
  }
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`EVM-family signing key slot id requires ${field}`);
  }
  return normalized;
}

function keyPart(value: unknown): string {
  return encodeURIComponent(requiredPart(value, 'non-empty components'));
}

function isEvmFamilySigningKeySlotIdShape(value: string): boolean {
  const parts = value.split(':');
  return (
    parts.length === 5 &&
    parts[0] === 'wallet-key' &&
    parts[1] === 'evm-family' &&
    parts.slice(2).every((part) => part.length > 0)
  );
}

export function parseEvmFamilySigningKeySlotId(
  raw: unknown,
): DomainIdParseResult<EvmFamilySigningKeySlotId> {
  const parsed = parseWalletKeyId(raw);
  if (!parsed.ok) return parsed;
  if (!isEvmFamilySigningKeySlotIdShape(String(parsed.value))) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message:
          'EVM-family signing key slot id must be wallet-key:evm-family:<walletId>:<signingRootId>:<signingRootVersion>',
      },
    };
  }
  return { ok: true, value: String(parsed.value) as EvmFamilySigningKeySlotId };
}

export function parseEvmFamilySigningKeySlotIdOrNull(
  raw: unknown,
): EvmFamilySigningKeySlotId | null {
  const parsed = parseEvmFamilySigningKeySlotId(raw);
  return parsed.ok ? parsed.value : null;
}

export function requireEvmFamilySigningKeySlotId(
  value: unknown,
  label = 'evmFamilySigningKeySlotId',
): EvmFamilySigningKeySlotId {
  const parsed = parseEvmFamilySigningKeySlotId(value);
  if (parsed.ok) return parsed.value;
  if (parsed.error.code === 'missing') throw new Error(`${label} is required`);
  throw new Error(`${label} must be an EVM-family signing key slot id`);
}

export function assertMatchingEvmFamilySigningKeySlotId(args: {
  expected: unknown;
  actual: unknown;
  expectedLabel?: string;
  actualLabel?: string;
  message?: string;
}): EvmFamilySigningKeySlotId {
  const expected = requireEvmFamilySigningKeySlotId(
    args.expected,
    args.expectedLabel || 'expected evmFamilySigningKeySlotId',
  );
  const actual = requireEvmFamilySigningKeySlotId(
    args.actual,
    args.actualLabel || 'actual evmFamilySigningKeySlotId',
  );
  if (String(actual) !== String(expected)) {
    throw new Error(args.message || `${args.actualLabel || 'evmFamilySigningKeySlotId'} mismatch`);
  }
  return actual;
}

export function assertEvmFamilySigningKeySlotIdMatchesPlan(args: {
  evmFamilySigningKeySlotId: unknown;
  walletId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  message?: string;
}): EvmFamilySigningKeySlotId {
  const actual = requireEvmFamilySigningKeySlotId(args.evmFamilySigningKeySlotId);
  const expected = deriveEvmFamilySigningKeySlotId({
    walletId: args.walletId,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
  });
  if (String(actual) !== String(expected)) {
    throw new Error(args.message || 'signing key slot id does not match wallet/signing-root scope');
  }
  return actual;
}

export function deriveEvmFamilySigningKeySlotId(input: {
  walletId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): EvmFamilySigningKeySlotId {
  const raw = [
    'wallet-key',
    'evm-family',
    keyPart(input.walletId),
    keyPart(input.signingRootId),
    keyPart(input.signingRootVersion),
  ].join(':');
  return requireEvmFamilySigningKeySlotId(raw);
}

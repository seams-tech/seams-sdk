import { parseWalletKeyId, type WalletKeyId } from './ids';

function walletKeyIdErrorMessage(label: string, code: 'missing' | 'invalid'): string {
  if (code === 'missing') return `${label} is required`;
  return `${label} must be a string`;
}

export function parseWalletKeyIdOrNull(value: unknown): WalletKeyId | null {
  const parsed = parseWalletKeyId(value);
  return parsed.ok ? parsed.value : null;
}

export function requireWalletKeyId(value: unknown, label = 'walletKeyId'): WalletKeyId {
  const parsed = parseWalletKeyId(value);
  if (parsed.ok) return parsed.value;
  throw new Error(walletKeyIdErrorMessage(label, parsed.error.code));
}

export function assertMatchingWalletKeyId(args: {
  expected: unknown;
  actual: unknown;
  expectedLabel?: string;
  actualLabel?: string;
  message?: string;
}): WalletKeyId {
  const expected = requireWalletKeyId(args.expected, args.expectedLabel || 'expected walletKeyId');
  const actual = requireWalletKeyId(args.actual, args.actualLabel || 'actual walletKeyId');
  if (String(actual) !== String(expected)) {
    throw new Error(args.message || `${args.actualLabel || 'walletKeyId'} mismatch`);
  }
  return actual;
}

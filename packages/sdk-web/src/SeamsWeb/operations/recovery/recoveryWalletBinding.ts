import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { WalletId } from '@shared/utils/domainIds';
import {
  ed25519KeyScopeIdFromString,
  walletIdFromString,
  type Ed25519KeyScopeId,
} from '@shared/utils/registrationIntent';
import { isObject } from '@shared/utils/validation';

export type RecoveryResolvedWalletBinding = {
  walletId: WalletId;
  nearAccountId: AccountId;
  ed25519KeyScopeId: Ed25519KeyScopeId;
  rpId: string;
  signerSlot: number;
};

function requireBindingString(raw: Record<string, unknown>, field: string, context: string): string {
  const value = String(raw[field] || '').trim();
  if (!value) throw new Error(`${context} returned missing ${field}`);
  return value;
}

function requirePositiveSignerSlot(value: unknown, context: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${context} returned invalid signerSlot`);
  }
  return Math.floor(parsed);
}

export function parseRecoveryResolvedWalletBinding(
  raw: unknown,
  context: string,
): RecoveryResolvedWalletBinding {
  if (!isObject(raw)) {
    throw new Error(`${context} returned missing walletBinding`);
  }
  const walletId = walletIdFromString(requireBindingString(raw, 'walletId', context));
  const nearAccountId = toAccountId(requireBindingString(raw, 'nearAccountId', context));
  const ed25519KeyScopeId = ed25519KeyScopeIdFromString(
    requireBindingString(raw, 'ed25519KeyScopeId', context),
  );
  const rpId = requireBindingString(raw, 'rpId', context);
  const signerSlot = requirePositiveSignerSlot(raw.signerSlot, context);
  return {
    walletId,
    nearAccountId,
    ed25519KeyScopeId,
    rpId,
    signerSlot,
  };
}

export function parseRecoveryResolvedWalletBindingFromResponse(
  raw: Record<string, unknown>,
  context: string,
): RecoveryResolvedWalletBinding {
  const bindingSource = isObject(raw.walletBinding) ? raw.walletBinding : raw;
  return parseRecoveryResolvedWalletBinding(bindingSource, context);
}

export function assertSameRecoveryResolvedWalletBinding(
  left: RecoveryResolvedWalletBinding,
  right: RecoveryResolvedWalletBinding,
  context: string,
): void {
  if (
    String(left.walletId) !== String(right.walletId) ||
    String(left.nearAccountId) !== String(right.nearAccountId) ||
    String(left.ed25519KeyScopeId) !== String(right.ed25519KeyScopeId) ||
    left.rpId !== right.rpId ||
    left.signerSlot !== right.signerSlot
  ) {
    throw new Error(`${context} returned mismatched wallet binding`);
  }
}

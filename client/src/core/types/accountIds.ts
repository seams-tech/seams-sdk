/**
 * Type-safe account ID system for NEAR account operations
 *
 * USAGE:
 * - AccountId: Use for all operations - on-chain, PRF salt derivation, storage, WebAuthn
 *
 * EXAMPLES:
 * - "serp1.w3a-relayer.testnet"
 * - "alice.near"
 * - "simple.testnet"
 */

import { validateNearAccountId } from '@shared/utils/validation';

// AccountId is a validated string at runtime. The optional brand keeps editor hints
// without making test fixtures and external string inputs unassignable.
export type AccountId = string & { readonly __brand?: 'AccountId' };
export type StrictAccountId = string & { readonly __brand: 'AccountId' };

/**
 * Convert and validate string to AccountId
 * Validates proper NEAR account format (must contain at least one dot)
 */
export function toAccountId(accountId: string): StrictAccountId {
  const validation = validateNearAccountId(accountId);
  if (!validation.valid) {
    throw new Error(`Invalid NEAR account ID: ${accountId}`);
  }
  return accountId as StrictAccountId;
}

/**
 * Account ID utilities
 */
export const AccountId = {
  validate: validateNearAccountId,
  to: toAccountId,
} as const;

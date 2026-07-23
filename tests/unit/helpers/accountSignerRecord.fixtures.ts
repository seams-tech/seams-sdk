import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';

/**
 * Builds a valid current-domain AccountSignerRecord for a threshold-ECDSA signer.
 * Tests override only the fields they exercise.
 */
export function seedAccountSignerRecord(
  overrides: Partial<AccountSignerRecord> = {},
): AccountSignerRecord {
  const nowMs = Date.now();
  return {
    profileId: 'alice.testnet',
    chainIdKey: 'tempo:42431',
    accountAddress: `0x${'11'.repeat(20)}`,
    signerId: `0x${'11'.repeat(20)}`,
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'active',
    addedAt: nowMs,
    updatedAt: nowMs,
    ...overrides,
  };
}

/**
 * Mirrors the production `activateAccountSigner` result shape for store mocks: echoes the
 * activation input back as the persisted signer row.
 */
export function accountSignerRecordFromActivateInput(
  input: ActivateAccountSignerInput,
  overrides: Partial<AccountSignerRecord> = {},
): AccountSignerRecord {
  return seedAccountSignerRecord({
    profileId: input.account.profileId,
    chainIdKey: input.account.chainIdKey,
    accountAddress: input.account.accountAddress,
    signerId: input.signer.signerId,
    signerType: input.signer.signerType,
    signerKind: input.signer.signerKind,
    signerAuthMethod: input.signer.signerAuthMethod,
    signerSource: input.signer.signerSource,
    signerSlot: input.preferredSlot || 1,
    ...(input.signer.metadata !== undefined ? { metadata: input.signer.metadata } : {}),
    ...overrides,
  });
}

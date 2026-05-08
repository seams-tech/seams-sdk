import { expect, test } from '@playwright/test';
import {
  buildRegistrationSmartAccountRecords,
} from '../../server/src/core/smartAccountRegistrationRecords';
import { createAccountSignerStore } from '../../server/src/core/AccountSignerStore';
import {
  createSmartAccountRecoverySubjectStore,
} from '../../server/src/core/SmartAccountRecoverySubjectStore';

test.describe('smart-account registration canonical records', () => {
  test('builds canonical signer and recovery-subject records for smart-account targets', async () => {
    const result = await (async () => {
      const built = buildRegistrationSmartAccountRecords({
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        signerSlot: 2,
        credentialIdB64u: 'cred-b64u',
        rpId: 'wallet.example.test',
        relayerKeyId: 'rk-1',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
        participantIds: [1, 2],
        smartAccountTargets: [
          {
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'sepolia',
            },
            factory: `0x${'bb'.repeat(20)}`,
            entry_point: `0x${'cc'.repeat(20)}`,
            recovery_authority: `0x${'dd'.repeat(20)}`,
            salt: '0x1234',
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
          {
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-testnet',
            },
            counterfactual_address: `0x${'22'.repeat(20)}`,
          },
        ],
        nowMs: 1_717_171_717_000,
      });

      const signerStore = createAccountSignerStore({
        config: null,
        logger: console,
        isNode: false,
      });
      const subjectStore = createSmartAccountRecoverySubjectStore({
        config: null,
        logger: console,
        isNode: false,
      });

      for (const record of built.accountSigners) {
        await signerStore.put(record);
      }
      for (const record of built.recoverySubjects) {
        await subjectStore.put(record);
      }

      const signersByUser = await signerStore.listByUserId('alice.testnet');
      const evmSigners = await signerStore.listByAccount({
        chainIdKey: 'evm:eip155:11155111',
        accountAddress: `0x${'11'.repeat(20)}`,
      });
      const recoverySubjects = await subjectStore.listByNearAccountId('alice.testnet');

      return {
        builtSignerCount: built.accountSigners.length,
        builtSubjectCount: built.recoverySubjects.length,
        signersByUser,
        evmSigners,
        recoverySubjects,
      };
    })();

    expect(result.builtSignerCount).toBe(2);
    expect(result.builtSubjectCount).toBe(2);
    expect(result.signersByUser).toHaveLength(2);
    expect(result.evmSigners).toHaveLength(1);
    expect(result.recoverySubjects).toHaveLength(2);

    expect(result.signersByUser[0]?.signerType).toBe('threshold');
    expect(result.signersByUser[0]?.status).toBe('active');
    expect(result.signersByUser[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.signersByUser[0]?.metadata?.relayerKeyId).toBe('rk-1');
    expect(result.signersByUser[0]?.metadata?.thresholdEcdsaPublicKeyB64u).toBe('group-public-key');
    expect(result.signersByUser[0]?.metadata?.signerSlot).toBe(2);

    expect(result.recoverySubjects[0]?.nearAccountId).toBe('alice.testnet');
    expect(result.recoverySubjects[0]?.metadata?.accountModel).toBe('erc4337');
    expect(result.recoverySubjects[0]?.metadata?.recoveryAuthority).toBe(`0x${'dd'.repeat(20)}`);
    expect(result.recoverySubjects[1]?.metadata?.accountModel).toBe('tempo-native');
  });

  test('deduplicates repeated smart-account targets by chain account', async () => {
    const result = await (async () => {
      return buildRegistrationSmartAccountRecords({
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        credentialIdB64u: 'cred-b64u',
        rpId: 'wallet.example.test',
        relayerKeyId: 'rk-1',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
        smartAccountTargets: [
          {
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 1,
              networkSlug: 'mainnet',
            },
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
          {
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 1,
              networkSlug: 'mainnet',
            },
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
        ],
      });
    })();

    expect(result.accountSigners).toHaveLength(1);
    expect(result.recoverySubjects).toHaveLength(1);
  });
});

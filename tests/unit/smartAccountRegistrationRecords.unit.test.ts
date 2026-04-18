import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('smart-account registration canonical records', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('builds canonical signer and recovery-subject records for smart-account targets', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const {
        buildRegistrationSmartAccountRecords,
        createAccountSignerStore,
        createSmartAccountRecoverySubjectStore,
      } = await import(paths.server);

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
            chain: 'evm',
            chain_id: 11155111,
            factory: `0x${'bb'.repeat(20)}`,
            entry_point: `0x${'cc'.repeat(20)}`,
            recovery_authority: `0x${'dd'.repeat(20)}`,
            salt: '0x1234',
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
          {
            chain: 'tempo',
            chain_id: 42431,
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
        chainIdKey: 'evm:11155111',
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
    }, { paths: IMPORT_PATHS });

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

  test('deduplicates repeated smart-account targets by chain account', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { buildRegistrationSmartAccountRecords } = await import(paths.server);
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
            chain: 'evm',
            chain_id: 1,
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
          {
            chain: 'evm',
            chain_id: 1,
            counterfactual_address: `0x${'11'.repeat(20)}`,
          },
        ],
      });
    }, { paths: IMPORT_PATHS });

    expect(result.accountSigners).toHaveLength(1);
    expect(result.recoverySubjects).toHaveLength(1);
  });
});

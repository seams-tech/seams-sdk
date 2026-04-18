import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('smart-account link-device canonical records', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('builds pending signer rows and linked-account projections from recovery subjects', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const {
        buildLinkDeviceSmartAccountRecords,
        createAccountSignerStore,
      } = await import(paths.server);

      const built = buildLinkDeviceSmartAccountRecords({
        userId: 'alice.testnet',
        signerSlot: 4,
        credentialIdB64u: 'cred-b64u',
        rpId: 'wallet.example.test',
        relayerKeyId: 'rk-ecdsa',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
        participantIds: [1, 2],
        recoverySubjects: [
          {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            createdAtMs: 1_717_171_717_000,
            updatedAtMs: 1_717_171_717_000,
            metadata: {
              accountModel: 'erc4337',
              chain: 'evm',
              chainId: 11155111,
              deployed: true,
              factory: `0x${'bb'.repeat(20)}`,
              entryPoint: `0x${'cc'.repeat(20)}`,
              salt: '0x1234',
              counterfactualAddress: `0x${'11'.repeat(20)}`,
            },
          },
          {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'tempo:42431',
            accountAddress: `0x${'22'.repeat(20)}`,
            createdAtMs: 1_717_171_717_000,
            updatedAtMs: 1_717_171_717_000,
            metadata: {
              accountModel: 'tempo-native',
              chain: 'tempo',
              chainId: 42431,
              deployed: false,
              counterfactualAddress: `0x${'22'.repeat(20)}`,
            },
          },
        ],
        nowMs: 1_818_181_818_000,
      });

      const signerStore = createAccountSignerStore({
        config: null,
        logger: console,
        isNode: false,
      });
      for (const record of built.accountSigners) {
        await signerStore.put(record);
      }
      const evmSigners = await signerStore.listByAccount({
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'11'.repeat(20)}`,
      });

      return {
        linkedAccounts: built.linkedAccounts,
        accountSigners: built.accountSigners,
        evmSigners,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.linkedAccounts).toHaveLength(2);
    expect(result.accountSigners).toHaveLength(2);
    expect(result.evmSigners).toHaveLength(1);
    expect(result.evmSigners[0]?.status).toBe('pending');
    expect(result.evmSigners[0]?.signerId).toBe(`0x${'aa'.repeat(20)}`);
    expect(result.evmSigners[0]?.metadata?.thresholdEcdsaPublicKeyB64u).toBe('group-public-key');
    expect(result.evmSigners[0]?.metadata?.signerSlot).toBe(4);
    expect(result.linkedAccounts[0]?.chainIdKey).toBe('evm:11155111');
    expect(result.linkedAccounts[0]?.accountModel).toBe('erc4337');
    expect(result.linkedAccounts[0]?.deployed).toBe(true);
    expect(result.linkedAccounts[1]?.chainIdKey).toBe('tempo:42431');
    expect(result.linkedAccounts[1]?.accountModel).toBe('tempo-native');
    expect(result.linkedAccounts[1]?.deployed).toBe(false);
  });

  test('deduplicates repeated recovery subjects by chain account', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { buildLinkDeviceSmartAccountRecords } = await import(paths.server);
      return buildLinkDeviceSmartAccountRecords({
        userId: 'alice.testnet',
        signerSlot: 2,
        credentialIdB64u: 'cred-b64u',
        rpId: 'wallet.example.test',
        relayerKeyId: 'rk-ecdsa',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
        thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
        recoverySubjects: [
          {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'evm:1',
            accountAddress: `0x${'11'.repeat(20)}`,
            createdAtMs: 1,
            updatedAtMs: 1,
            metadata: { chain: 'evm', chainId: 1 },
          },
          {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'evm:1',
            accountAddress: `0x${'11'.repeat(20)}`,
            createdAtMs: 2,
            updatedAtMs: 2,
            metadata: { chain: 'evm', chainId: 1 },
          },
        ],
      });
    }, { paths: IMPORT_PATHS });

    expect(result.linkedAccounts).toHaveLength(1);
    expect(result.accountSigners).toHaveLength(1);
  });
});

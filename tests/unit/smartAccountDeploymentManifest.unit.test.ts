import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('smart-account deployment manifest builder', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('derives undeployed owner manifest from canonical account signer state', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { buildCanonicalSmartAccountDeploymentManifest } = await import(paths.server);
      return buildCanonicalSmartAccountDeploymentManifest({
        recoverySubject: {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'11'.repeat(20)}`,
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'evm',
            chainId: 11155111,
            accountModel: 'erc4337',
            deployed: false,
            factory: `0x${'22'.repeat(20)}`,
            entryPoint: `0x${'33'.repeat(20)}`,
            salt: '0x1234',
            counterfactualAddress: `0x${'11'.repeat(20)}`,
          },
        },
        signers: [
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerType: 'threshold',
            signerId: `0x${'aa'.repeat(20)}`,
            status: 'active',
            createdAtMs: 1,
            updatedAtMs: 1,
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerType: 'threshold',
            signerId: `0x${'bb'.repeat(20)}`,
            status: 'pending',
            createdAtMs: 2,
            updatedAtMs: 2,
          },
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'11'.repeat(20)}`,
            signerType: 'threshold',
            signerId: `0x${'cc'.repeat(20)}`,
            status: 'revoked',
            createdAtMs: 3,
            updatedAtMs: 3,
          },
        ],
        materializedAtMs: 1234,
      });
    }, { paths: IMPORT_PATHS });

    expect(result?.version).toBe('smart_account_deployment_manifest_v1');
    expect(result?.chainIdKey).toBe('evm:11155111');
    expect(result?.deployed).toBe(false);
    expect(result?.ownerAddresses).toEqual([
      `0x${'aa'.repeat(20)}`,
      `0x${'bb'.repeat(20)}`,
    ]);
    expect(result?.activeOwnerAddresses).toEqual([`0x${'aa'.repeat(20)}`]);
    expect(result?.pendingOwnerAddresses).toEqual([`0x${'bb'.repeat(20)}`]);
    expect(result?.owners).toHaveLength(2);
    expect(result?.counterfactualAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(result?.materializedAtMs).toBe(1234);
  });
});

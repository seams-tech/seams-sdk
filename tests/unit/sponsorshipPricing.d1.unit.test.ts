import { expect, test } from '@playwright/test';
import {
  createD1ConsoleSponsorshipPricingService,
  seedD1ConsoleStaticEvmSponsorshipPricingRule,
} from '../../packages/console-server-ts/src/sponsorshipPricing/d1';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

const TEST_NOW_MS = 1_790_000_000_000;

function testNow(): Date {
  return new Date(TEST_NOW_MS);
}

async function seedEnvironment(database: ReturnType<typeof createTemporaryD1Database>['database']) {
  await database.exec(`
    INSERT INTO organizations (
      namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms
    ) VALUES (
      'seams-test', 'org_test', 'Test Org', 'test-org', 'user_test', 'ACTIVE', 1, 1
    );
    INSERT INTO projects (
      namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms
    ) VALUES (
      'seams-test', 'proj_test', 'org_test', 'Test Project', 'test-project', 'ACTIVE', 1, 1
    );
    INSERT INTO environments (
      namespace, id, org_id, project_id, env_key, signing_root_version, name, status, created_at_ms, updated_at_ms
    ) VALUES (
      'seams-test', 'env_test', 'org_test', 'proj_test', 'dev', 'default', 'Development', 'ACTIVE', 1, 1
    );
  `);
}

test('D1 static EVM sponsorship pricing seeds and quotes exact versions', async () => {
  const temp = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));
    await seedEnvironment(temp.database);

    await seedD1ConsoleStaticEvmSponsorshipPricingRule({
      database: temp.database,
      namespace: 'seams-test',
      orgId: 'org_test',
      projectId: 'proj_test',
      environmentId: 'env_test',
      policyId: 'pol_test',
      chainId: 42_431,
      pricingVersion: 'tempo-static-v1',
      estimateFeePerGasWei: '100',
      minorPerWeiNumerator: '2',
      minorPerWeiDenominator: '5',
      minSpendMinor: 10,
      createdBy: 'platform_admin_test',
      effectiveFromMs: TEST_NOW_MS - 1_000,
      now: testNow,
    });

    const pricing = await createD1ConsoleSponsorshipPricingService({
      database: temp.database,
      namespace: 'seams-test',
      ensureSchema: false,
      now: testNow,
    });

    await expect(
      pricing.estimateSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'env_test',
        policyId: 'pol_test',
        accountRef: null,
        targetRef: '0x2222222222222222222222222222222222222222',
        chainId: 42_431,
        requestDetails: {
          call: {
            gasLimit: '21000',
          },
        },
      }),
    ).resolves.toEqual({
      spendMinor: 840_000,
      pricingVersion: 'tempo-static-v1',
    });

    await expect(
      pricing.finalizeSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'env_test',
        policyId: 'pol_test',
        accountRef: null,
        targetRef: '0x2222222222222222222222222222222222222222',
        chainId: 42_431,
        txOrExecutionRef: '0xabc',
        receiptStatus: 'success',
        feeUnit: 'wei',
        feeAmount: '1234',
        requestDetails: {},
        estimatedSpendMinor: 840_000,
        estimatedPricingVersion: 'tempo-static-v1',
      }),
    ).resolves.toEqual({
      spendMinor: 494,
      pricingVersion: 'tempo-static-v1',
    });

    await expect(
      pricing.finalizeSponsoredExecutionSpend({
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: 'evm_eoa',
        environmentId: 'env_test',
        policyId: 'pol_test',
        accountRef: null,
        targetRef: '0x2222222222222222222222222222222222222222',
        chainId: 42_431,
        txOrExecutionRef: '0xabc',
        receiptStatus: 'success',
        feeUnit: 'wei',
        feeAmount: '1234',
        requestDetails: {},
        estimatedSpendMinor: 840_000,
        estimatedPricingVersion: 'tempo-static-v2',
      }),
    ).rejects.toMatchObject({
      code: 'sponsorship_pricing_unavailable',
      status: 503,
    });
  } finally {
    cleanupTemporaryD1Database(temp.tempDir);
  }
});

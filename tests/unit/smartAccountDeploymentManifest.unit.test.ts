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

  test('derives undeployed owner manifest from canonical account signer state', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const {
          buildCanonicalEvmSmartAccountDeploymentPlan,
          buildCanonicalSmartAccountDeploymentManifest,
          buildRecoveryAuthorityAuthorizationDigest,
        } = await import(paths.server);
        const manifest = buildCanonicalSmartAccountDeploymentManifest({
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
              recoveryAuthority: `0x${'44'.repeat(20)}`,
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
        const authorization = buildRecoveryAuthorityAuthorizationDigest({
          chainId: 11155111,
          verifyingContract: `0x${'11'.repeat(20)}`,
          nearAccountId: 'alice.testnet',
          newNearPublicKey: 'ed25519:new-key',
          newOwnerAddress: `0x${'55'.repeat(20)}`,
          recoverySessionId: 'session-1',
          deadlineEpochSeconds: 1_717_171_717,
        });
        const evmDeploymentPlan = manifest
          ? buildCanonicalEvmSmartAccountDeploymentPlan(manifest)
          : null;
        return {
          manifest,
          evmDeploymentPlan,
          recoveryAuthorizationNearAccountIdHash: authorization.payload.nearAccountIdHash,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.manifest?.version).toBe('smart_account_deployment_manifest_v1');
    expect(result?.manifest?.chainIdKey).toBe('evm:11155111');
    expect(result?.manifest?.deployed).toBe(false);
    expect(result?.manifest?.ownerAddresses).toEqual([
      `0x${'aa'.repeat(20)}`,
      `0x${'bb'.repeat(20)}`,
    ]);
    expect(result?.manifest?.activeOwnerAddresses).toEqual([`0x${'aa'.repeat(20)}`]);
    expect(result?.manifest?.pendingOwnerAddresses).toEqual([`0x${'bb'.repeat(20)}`]);
    expect(result?.manifest?.owners).toHaveLength(2);
    expect(result?.manifest?.nearAccountIdHash).toBe(
      result?.recoveryAuthorizationNearAccountIdHash,
    );
    expect(result?.manifest?.recoveryAuthority).toBe(`0x${'44'.repeat(20)}`);
    expect(result?.manifest?.counterfactualAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(result?.manifest?.materializedAtMs).toBe(1234);
    expect(result?.evmDeploymentPlan?.version).toBe('evm_smart_account_deployment_plan_v1');
    expect(result?.evmDeploymentPlan?.salt).toBe(`0x${'0'.repeat(60)}1234`);
    expect(result?.evmDeploymentPlan?.createAccountCalldata).toMatch(/^0xf8a59370/);
    expect(result?.evmDeploymentPlan?.matchesAccountAddress).toBe(false);
  });

  test('marks when the predicted factory address matches the canonical account address', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { buildCanonicalEvmSmartAccountDeploymentPlan } = await import(paths.server);
        const baseManifest = {
          version: 'smart_account_deployment_manifest_v1',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'11'.repeat(20)}`,
          nearAccountIdHash: `0x${'aa'.repeat(32)}`,
          chain: 'evm',
          chainId: 11155111,
          accountModel: 'erc4337',
          deployed: false,
          ownerAddresses: [`0x${'bb'.repeat(20)}`],
          activeOwnerAddresses: [`0x${'bb'.repeat(20)}`],
          pendingOwnerAddresses: [],
          owners: [],
          materializedAtMs: 1234,
          source: 'canonical_account_signer',
          factory: `0x${'22'.repeat(20)}`,
          entryPoint: `0x${'33'.repeat(20)}`,
          recoveryAuthority: `0x${'44'.repeat(20)}`,
          salt: '0x1234',
        } as const;
        const initialPlan = buildCanonicalEvmSmartAccountDeploymentPlan(baseManifest);
        const matchedPlan = initialPlan
          ? buildCanonicalEvmSmartAccountDeploymentPlan({
              ...baseManifest,
              accountAddress: initialPlan.predictedAddress,
              counterfactualAddress: initialPlan.predictedAddress,
            })
          : null;
        return {
          initialPlan,
          matchedPlan,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.initialPlan?.predictedAddress).toMatch(/^0x[0-9a-f]{40}$/);
    expect(result?.initialPlan?.matchesAccountAddress).toBe(false);
    expect(result?.matchedPlan?.predictedAddress).toBe(result?.initialPlan?.predictedAddress);
    expect(result?.matchedPlan?.matchesAccountAddress).toBe(true);
  });

  test('preserves canonical owner ordering in manifest owners and evm initData', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const {
          buildCanonicalEvmSmartAccountDeploymentPlan,
          buildCanonicalSmartAccountDeploymentManifest,
        } = await import(paths.server);

        const manifest = buildCanonicalSmartAccountDeploymentManifest({
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
              recoveryAuthority: `0x${'44'.repeat(20)}`,
              salt: '0x1234',
            },
          },
          signers: [
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              signerType: 'threshold',
              signerId: `0x${'dd'.repeat(20)}`,
              status: 'pending',
              createdAtMs: 40,
              updatedAtMs: 40,
              metadata: { signerSlot: 4 },
            },
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              signerType: 'threshold',
              signerId: `0x${'cc'.repeat(20)}`,
              status: 'active',
              createdAtMs: 20,
              updatedAtMs: 20,
              metadata: { signerSlot: 2 },
            },
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              signerType: 'threshold',
              signerId: `0x${'bb'.repeat(20)}`,
              status: 'active',
              createdAtMs: 10,
              updatedAtMs: 10,
              metadata: { signerSlot: 1 },
            },
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              signerType: 'threshold',
              signerId: `0x${'aa'.repeat(20)}`,
              status: 'pending',
              createdAtMs: 30,
              updatedAtMs: 30,
            },
          ],
          materializedAtMs: 1234,
        });

        const plan = manifest ? buildCanonicalEvmSmartAccountDeploymentPlan(manifest) : null;
        const ownerWords: string[] = [];
        const initData = String(plan?.initData || '');
        if (/^0x[0-9a-f]+$/i.test(initData)) {
          const hex = initData.slice(2);
          const ownersLengthOffset = 128 * 2;
          const ownersLength = Number.parseInt(
            hex.slice(ownersLengthOffset, ownersLengthOffset + 64),
            16,
          );
          for (let index = 0; index < ownersLength; index += 1) {
            const start = ownersLengthOffset + 64 + index * 64;
            ownerWords.push(`0x${hex.slice(start + 24, start + 64)}`);
          }
        }

        return {
          ownerAddresses: manifest?.ownerAddresses || null,
          owners:
            manifest?.owners?.map((owner) => ({
              signerId: owner.signerId,
              status: owner.status,
              signerSlot: owner.signerSlot ?? null,
            })) || null,
          initOwners: ownerWords,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.ownerAddresses).toEqual([
      `0x${'bb'.repeat(20)}`,
      `0x${'cc'.repeat(20)}`,
      `0x${'dd'.repeat(20)}`,
      `0x${'aa'.repeat(20)}`,
    ]);
    expect(result?.owners).toEqual([
      {
        signerId: `0x${'bb'.repeat(20)}`,
        status: 'active',
        signerSlot: 1,
      },
      {
        signerId: `0x${'cc'.repeat(20)}`,
        status: 'active',
        signerSlot: 2,
      },
      {
        signerId: `0x${'dd'.repeat(20)}`,
        status: 'pending',
        signerSlot: 4,
      },
      {
        signerId: `0x${'aa'.repeat(20)}`,
        status: 'pending',
        signerSlot: null,
      },
    ]);
    expect(result?.initOwners).toEqual(result?.ownerAddresses);
  });

  test('sync persists canonical evm deployment-plan metadata and clears stale non-evm plan state', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { syncCanonicalSmartAccountDeploymentManifest } = await import(paths.server);

        const evmRecord = {
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
            recoveryAuthority: `0x${'44'.repeat(20)}`,
            salt: '0x1234',
            counterfactualAddress: `0x${'11'.repeat(20)}`,
          },
        };
        const evmWrites: Array<Record<string, unknown>> = [];
        const evmService = {
          async getSmartAccountRecoverySubjectByAccount() {
            return { ok: true, record: evmRecord };
          },
          async listAccountSignersByAccount() {
            return {
              ok: true,
              records: [
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
              ],
            };
          },
          async putSmartAccountRecoverySubject(record: Record<string, unknown>) {
            evmWrites.push(record);
            return { ok: true, record };
          },
        };

        const tempoRecord = {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'tempo:42431',
          accountAddress: `0x${'22'.repeat(20)}`,
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'tempo',
            chainId: 42431,
            accountModel: 'tempo-native',
            deployed: false,
            evmDeploymentPlan: {
              version: 'stale',
            },
            evmDeploymentPlanUpdatedAtMs: 123,
          },
        };
        const tempoWrites: Array<Record<string, unknown>> = [];
        const tempoService = {
          async getSmartAccountRecoverySubjectByAccount() {
            return { ok: true, record: tempoRecord };
          },
          async listAccountSignersByAccount() {
            return {
              ok: true,
              records: [
                {
                  version: 'account_signer_v1',
                  userId: 'alice.testnet',
                  chainIdKey: 'tempo:42431',
                  accountAddress: `0x${'22'.repeat(20)}`,
                  signerType: 'threshold',
                  signerId: `0x${'bb'.repeat(20)}`,
                  status: 'active',
                  createdAtMs: 1,
                  updatedAtMs: 1,
                },
              ],
            };
          },
          async putSmartAccountRecoverySubject(record: Record<string, unknown>) {
            tempoWrites.push(record);
            return { ok: true, record };
          },
        };

        await syncCanonicalSmartAccountDeploymentManifest({
          authService: evmService as any,
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'11'.repeat(20)}`,
          materializedAtMs: 4321,
        });
        await syncCanonicalSmartAccountDeploymentManifest({
          authService: tempoService as any,
          chainIdKey: 'tempo:42431',
          accountAddress: `0x${'22'.repeat(20)}`,
          materializedAtMs: 8765,
        });

        return {
          evmMetadata: evmWrites[0]?.metadata,
          tempoMetadata: tempoWrites[0]?.metadata,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.evmMetadata?.deploymentManifest?.ownerAddresses).toEqual([
      `0x${'aa'.repeat(20)}`,
    ]);
    expect(result?.evmMetadata?.evmDeploymentPlan?.predictedAddress).toMatch(/^0x[0-9a-f]{40}$/);
    expect(result?.evmMetadata?.evmDeploymentPlan?.createAccountCalldata).toMatch(/^0xf8a59370/);
    expect(result?.evmMetadata?.evmDeploymentPlanUpdatedAtMs).toBe(4321);
    expect(result?.tempoMetadata?.deploymentManifest?.ownerAddresses).toEqual([
      `0x${'bb'.repeat(20)}`,
    ]);
    expect(result?.tempoMetadata?.evmDeploymentPlan).toBeUndefined();
    expect(result?.tempoMetadata?.evmDeploymentPlanUpdatedAtMs).toBeUndefined();
  });
});

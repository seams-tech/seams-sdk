import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  deployment: '/sdk/esm/core/signingEngine/orchestration/smartAccountDeployment.js',
} as const;

test.describe('smart-account deployment request assembly', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('fetches canonical manifest before calling the custom deploy endpoint', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { deploySmartAccountForChain } = await import(paths.deployment);
      const calls: Array<Record<string, unknown>> = [];
      const originalFetch = globalThis.fetch;
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const body = init?.body ? JSON.parse(String(init.body)) : null;
        calls.push({
          url,
          method: init?.method || 'GET',
          headers:
            init?.headers && typeof init.headers === 'object'
              ? Object.fromEntries(new Headers(init.headers).entries())
              : {},
          body,
        });
        if (url.endsWith('/smart-account/deployment/manifest')) {
          return new Response(
            JSON.stringify({
              ok: true,
              manifest: {
                version: 'smart_account_deployment_manifest_v1',
                chainIdKey: 'evm:11155111',
                accountAddress: '0xabc111',
                chain: 'evm',
                chainId: 11155111,
                accountModel: 'erc4337',
                deployed: false,
                ownerAddresses: [`0x${'11'.repeat(20)}`],
                activeOwnerAddresses: [`0x${'11'.repeat(20)}`],
                pendingOwnerAddresses: [],
                owners: [],
                materializedAtMs: 1234,
                source: 'canonical_account_signer',
                nearAccountIdHash: `0x${'aa'.repeat(32)}`,
                factory: `0x${'22'.repeat(20)}`,
                entryPoint: `0x${'33'.repeat(20)}`,
                recoveryAuthority: `0x${'44'.repeat(20)}`,
                salt: `0x${'0'.repeat(60)}1234`,
                counterfactualAddress: '0xabc111',
              },
              evmDeploymentPlan: {
                version: 'evm_smart_account_deployment_plan_v1',
                factory: `0x${'22'.repeat(20)}`,
                salt: `0x${'0'.repeat(60)}1234`,
                initData: '0xinit',
                initDataHash: `0x${'55'.repeat(32)}`,
                deploymentSalt: `0x${'66'.repeat(32)}`,
                accountCreationCodeHash: `0x${'77'.repeat(32)}`,
                predictedAddress: '0xabc111',
                matchesAccountAddress: true,
                createAccountCalldata: '0xf8a59370deadbeef',
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: true, deploymentTxHash: '0xdeploytxhash' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      try {
        const deployed = await deploySmartAccountForChain(
          {
            network: {
              relayer: {
                url: 'https://relay.example.test',
                routes: {
                  delegateAction: '/signed-delegate',
                  smartAccountDeploy: '/deploy-smart-account',
                },
                smartAccountDeployment: {
                  mode: 'enforce',
                  maxAttempts: 2,
                },
                emailRecovery: {
                  minBalanceYocto: '1',
                  pollingIntervalMs: 1000,
                  maxPollingDurationMs: 1000,
                  pendingTtlMs: 1000,
                  mailtoAddress: 'recover@example.test',
                  emailDkimVerifierContract: 'dkim.near',
                },
              },
            },
          } as any,
          {
            nearAccountId: 'alice.testnet' as any,
            chain: 'evm',
            chainId: 11155111,
            account: {
              profileId: 'profile-1',
              chainIdKey: 'evm:11155111',
              accountAddress: '0xabc111',
              accountModel: 'erc4337',
              isPrimary: true,
              deployed: false,
              factory: '0xfactory',
              entryPoint: '0xentry',
              salt: '0xsalt',
              counterfactualAddress: '0xabc111',
            },
          },
          {
            relayerUrl: 'https://relay.example.test',
            thresholdSessionJwt: 'threshold-jwt',
          },
        );
        return { deployed, calls };
      } finally {
        globalThis.fetch = originalFetch;
      }
    }, { paths: IMPORT_PATHS });

    expect(result.deployed.ok).toBe(true);
    expect(result.deployed.deploymentTxHash).toBe('0xdeploytxhash');
    expect(result.calls).toHaveLength(2);
    expect(result.calls[0]?.url).toBe('https://relay.example.test/smart-account/deployment/manifest');
    expect(result.calls[0]?.headers).toEqual(
      expect.objectContaining({
        authorization: 'Bearer threshold-jwt',
      }),
    );
    expect(result.calls[1]?.url).toBe('https://relay.example.test/deploy-smart-account');
    expect(result.calls[1]?.body).toEqual(
      expect.objectContaining({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainId: 11155111,
        accountAddress: '0xabc111',
        accountModel: 'erc4337',
        deploymentManifest: expect.objectContaining({
          counterfactualAddress: '0xabc111',
          ownerAddresses: [`0x${'11'.repeat(20)}`],
        }),
        evmDeploymentPlan: expect.objectContaining({
          predictedAddress: '0xabc111',
          createAccountCalldata: '0xf8a59370deadbeef',
        }),
      }),
    );
    const requestBody = result.calls[1]?.body as any;
    expect(requestBody?.factory).toBeUndefined();
    expect(requestBody?.entryPoint).toBeUndefined();
    expect(requestBody?.salt).toBeUndefined();
  });
});

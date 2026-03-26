import { expect, test } from '@playwright/test';
import { createEvmSmartAccountDeployHandler } from '../../server/src/router/evmSmartAccountDeploy';

function makeBaseRequest() {
  return {
    nearAccountId: 'alice.testnet',
    chain: 'evm' as const,
    chainId: 11155111,
    accountAddress: `0x${'11'.repeat(20)}`,
    accountModel: 'erc4337',
    deploymentManifest: {
      version: 'smart_account_deployment_manifest_v1' as const,
      chainIdKey: 'evm:11155111',
      accountAddress: `0x${'11'.repeat(20)}`,
      nearAccountIdHash: `0x${'aa'.repeat(32)}` as `0x${string}`,
      chain: 'evm' as const,
      chainId: 11155111,
      accountModel: 'erc4337' as const,
      deployed: false,
      ownerAddresses: [`0x${'33'.repeat(20)}`],
      activeOwnerAddresses: [`0x${'33'.repeat(20)}`],
      pendingOwnerAddresses: [],
      owners: [],
      materializedAtMs: 1,
      source: 'canonical_account_signer' as const,
      factory: `0x${'22'.repeat(20)}`,
      recoveryAuthority: `0x${'44'.repeat(20)}`,
      salt: '0x1234',
      counterfactualAddress: `0x${'11'.repeat(20)}`,
    },
    evmDeploymentPlan: {
      version: 'evm_smart_account_deployment_plan_v1' as const,
      factory: `0x${'22'.repeat(20)}` as `0x${string}`,
      salt: `0x${'00'.repeat(30)}1234` as `0x${string}`,
      initData: `0x${'55'.repeat(32)}` as `0x${string}`,
      initDataHash: `0x${'66'.repeat(32)}` as `0x${string}`,
      deploymentSalt: `0x${'77'.repeat(32)}` as `0x${string}`,
      accountCreationCodeHash: `0x${'88'.repeat(32)}` as `0x${string}`,
      predictedAddress: `0x${'11'.repeat(20)}` as `0x${string}`,
      matchesAccountAddress: true,
      createAccountCalldata: `0xf8a59370${'99'.repeat(32)}` as `0x${string}`,
    },
  };
}

test.describe('evm smart-account deploy hook', () => {
  test('skips non-evm chains without breaking registration deploy orchestration', async () => {
    const handler = createEvmSmartAccountDeployHandler({ config: null, logger: null });
    const result = await handler({
      ...makeBaseRequest(),
      chain: 'tempo',
      chainId: 42431,
      accountModel: 'tempo-native',
      evmDeploymentPlan: undefined,
    });
    expect(result).toEqual({
      ok: true,
      code: 'assumed_deployed',
      message: 'Non-EVM smart-account deployment is handled outside the EVM deploy adapter',
    });
  });

  test('rejects canonical plan mismatches before any rpc calls', async () => {
    const handler = createEvmSmartAccountDeployHandler({
      config: {
        executorsByChain: new Map([
          [
            11155111,
            {
              chainId: 11155111,
              rpcUrl: 'https://rpc.example.test',
              sponsorAddress: '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
              sponsorPrivateKeyHex:
                '0x1111111111111111111111111111111111111111111111111111111111111111',
              maxPriorityFeePerGasFloor: 2_000_000_000n,
              maxFeePerGasFloor: 40_000_000_000n,
            },
          ],
        ]),
      },
      logger: null,
    });
    const result = await handler({
      ...makeBaseRequest(),
      accountAddress: `0x${'12'.repeat(20)}`,
    });
    expect(result).toEqual({
      ok: false,
      code: 'deployment_plan_account_mismatch',
      message: 'Canonical EVM deployment plan does not match the requested smart-account address',
    });
  });

  test('broadcasts the canonical factory deployment call from evmDeploymentPlan', async () => {
    const handler = createEvmSmartAccountDeployHandler({
      config: {
        executorsByChain: new Map([
          [
            11155111,
            {
              chainId: 11155111,
              rpcUrl: 'https://rpc.example.test',
              sponsorAddress: '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
              sponsorPrivateKeyHex:
                '0x1111111111111111111111111111111111111111111111111111111111111111',
              maxPriorityFeePerGasFloor: 2_000_000_000n,
              maxFeePerGasFloor: 40_000_000_000n,
            },
          ],
        ]),
      },
      logger: null,
    });

    const requests: Array<{ method: string; params: unknown[] }> = [];
    const txHash = `0x${'ab'.repeat(32)}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || '{}')) as {
        id: number;
        method: string;
        params: unknown[];
      };
      requests.push({ method: body.method, params: body.params });
      const reply = (result: unknown) =>
        new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      switch (body.method) {
        case 'eth_getCode':
          return reply('0x');
        case 'eth_estimateGas':
          return reply('0x61a80');
        case 'eth_getTransactionCount':
          return reply('0x1');
        case 'eth_getBlockByNumber':
          return reply({ number: '0x10', baseFeePerGas: '0x77359400' });
        case 'eth_maxPriorityFeePerGas':
          return reply('0x3b9aca00');
        case 'eth_gasPrice':
          return reply('0x77359400');
        case 'eth_sendRawTransaction':
          return reply(txHash);
        case 'eth_getTransactionReceipt':
          return reply({
            status: '0x1',
            blockNumber: '0x10',
            gasUsed: '0x5208',
            effectiveGasPrice: '0x77359400',
          });
        default:
          throw new Error(`Unexpected rpc method: ${body.method}`);
      }
    }) as typeof fetch;

    try {
      const result = await handler(makeBaseRequest());
      expect(result).toEqual({
        ok: true,
        deploymentTxHash: txHash,
        code: 'deployed',
      });
      expect(requests.map((entry) => entry.method)).toEqual([
        'eth_getCode',
        'eth_estimateGas',
        'eth_getTransactionCount',
        'eth_getBlockByNumber',
        'eth_maxPriorityFeePerGas',
        'eth_gasPrice',
        'eth_sendRawTransaction',
        'eth_getTransactionReceipt',
        'eth_getTransactionReceipt',
      ]);
      expect(requests[1]?.params[0]).toEqual({
        from: '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
        to: `0x${'22'.repeat(20)}`,
        value: '0x0',
        data: `0xf8a59370${'99'.repeat(32)}`,
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

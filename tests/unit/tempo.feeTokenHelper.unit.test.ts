import { expect, test } from '@playwright/test';
import { SDK_ESM_PATHS, setupBasicPasskeyTest } from '../setup';

test.describe('Tempo fee token helpers', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('encodes setUserToken(address) calldata and default fee-manager call', async ({ page }) => {
    const result = await page.evaluate(async (indexPath) => {
      const mod = await import(indexPath);
      const token = '0x20c0000000000000000000000000000000000001';
      const user = '0x8454d149beb26e3e3fc5ed1c87fb0b2a1b7b6c2c';
      const calldata = mod.encodeTempoSetUserTokenCalldata(token);
      const userTokensCallData = mod.encodeTempoUserTokensCalldata(user);
      const call = mod.buildTempoSetUserTokenCall({ token });
      const decodedToken = mod.decodeTempoUserTokenResult(
        `0x000000000000000000000000${token.slice(2)}`,
      );
      const decodedUnset = mod.decodeTempoUserTokenResult(
        '0x0000000000000000000000000000000000000000000000000000000000000000',
      );
      return {
        feeManager: mod.TEMPO_FEE_MANAGER_CONTRACT,
        alphaToken: mod.TEMPO_ALPHA_USD_FEE_TOKEN,
        selector: mod.TEMPO_SET_USER_TOKEN_SELECTOR,
        userTokensSelector: mod.TEMPO_USER_TOKENS_SELECTOR,
        calldata,
        userTokensCallData,
        callTo: call.to,
        callValue: String(call.value),
        callInput: call.input,
        callAbiName: Array.isArray(call.abi) ? call.abi[0]?.name : null,
        callAbiType: Array.isArray(call.abi) ? call.abi[0]?.type : null,
        callAbiInputType:
          Array.isArray(call.abi) && Array.isArray(call.abi[0]?.inputs)
            ? call.abi[0]?.inputs?.[0]?.type
            : null,
        decodedToken,
        decodedUnset,
      };
    }, SDK_ESM_PATHS.advanced);

    const expectedCalldata =
      '0xe789744400000000000000000000000020c0000000000000000000000000000000000001';
    const expectedUserTokensCallData =
      '0xed498fa80000000000000000000000008454d149beb26e3e3fc5ed1c87fb0b2a1b7b6c2c';

    expect(result.feeManager).toBe('0xfeec000000000000000000000000000000000000');
    expect(result.alphaToken).toBe('0x20c0000000000000000000000000000000000001');
    expect(result.selector).toBe('0xe7897444');
    expect(result.userTokensSelector).toBe('0xed498fa8');
    expect(result.calldata).toBe(expectedCalldata);
    expect(result.userTokensCallData).toBe(expectedUserTokensCallData);
    expect(result.callTo).toBe(result.feeManager);
    expect(result.callValue).toBe('0');
    expect(result.callInput).toBe(expectedCalldata);
    expect(result.callAbiName).toBe('setUserToken');
    expect(result.callAbiType).toBe('function');
    expect(result.callAbiInputType).toBe('address');
    expect(result.decodedToken).toBe('0x20c0000000000000000000000000000000000001');
    expect(result.decodedUnset).toBeNull();
  });

  test('reads, validates, and builds a FeeManager preference transaction', async ({ page }) => {
    const result = await page.evaluate(async (indexPath) => {
      const mod = await import(indexPath);
      const feeToken = '0x20c0000000000000000000000000000000000001';
      const account = '0x8454d149beb26e3e3fc5ed1c87fb0b2a1b7b6c2c';
      const addressWord = `0x${'0'.repeat(24)}${feeToken.slice(2)}`;
      const usdResult = `0x${'20'.padStart(64, '0')}${'3'.padStart(64, '0')}${'555344'.padEnd(64, '0')}`;
      const pausedResult = `0x${'0'.repeat(64)}`;
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async (_input, init) => {
        const body = JSON.parse(String(init?.body || '{}')) as {
          id: number;
          params?: Array<{ data?: string }>;
        };
        const selector = String(body.params?.[0]?.data || '').slice(0, 10);
        const rpcResult =
          selector === mod.TEMPO_USER_TOKENS_SELECTOR
            ? addressWord
            : selector === mod.TEMPO_TOKEN_CURRENCY_SELECTOR
              ? usdResult
              : pausedResult;
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: rpcResult }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      };
      try {
        const preference = await mod.readTempoFeeTokenPreference({
          rpcUrl: 'https://rpc.example',
          account,
        });
        const validation = await mod.validateTempoFeeToken({
          rpcUrl: 'https://rpc.example',
          feeToken,
        });
        const request = mod.buildTempoSetUserTokenRequest({
          chainId: 42431,
          feeToken,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 1_000_000n,
        });
        return {
          preference,
          validation,
          request: {
            chain: request.chain,
            kind: request.kind,
            chainId: request.tx.chainId,
            to: request.tx.to,
            data: request.tx.data,
            gasLimit: String(request.tx.gasLimit),
          },
        };
      } finally {
        globalThis.fetch = originalFetch;
      }
    }, SDK_ESM_PATHS.advanced);

    expect(result.preference).toBe('0x20c0000000000000000000000000000000000001');
    expect(result.validation).toEqual({
      kind: 'valid',
      feeToken: '0x20c0000000000000000000000000000000000001',
      currency: 'USD',
      paused: false,
    });
    expect(result.request).toEqual({
      chain: 'evm',
      kind: 'eip1559',
      chainId: 42431,
      to: '0xfeec000000000000000000000000000000000000',
      data: '0xe789744400000000000000000000000020c0000000000000000000000000000000000001',
      gasLimit: '1000000',
    });
  });

  test('reports unsupported currencies and paused USD tokens', async ({ page }) => {
    const result = await page.evaluate(async (indexPath) => {
      const mod = await import(indexPath);
      const feeToken = '0x20c0000000000000000000000000000000000001';
      const originalFetch = globalThis.fetch;
      let currencyResult = `0x${'20'.padStart(64, '0')}${'3'.padStart(64, '0')}${'455552'.padEnd(64, '0')}`;
      let pausedResult = `0x${'0'.repeat(64)}`;
      globalThis.fetch = async (_input, init) => {
        const body = JSON.parse(String(init?.body || '{}')) as {
          params?: Array<{ data?: string }>;
        };
        const selector = String(body.params?.[0]?.data || '').slice(0, 10);
        const rpcResult =
          selector === mod.TEMPO_TOKEN_CURRENCY_SELECTOR ? currencyResult : pausedResult;
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: rpcResult }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      };
      try {
        const unsupported = await mod.validateTempoFeeToken({
          rpcUrl: 'https://rpc.example',
          feeToken,
        });
        currencyResult = `0x${'20'.padStart(64, '0')}${'3'.padStart(64, '0')}${'555344'.padEnd(64, '0')}`;
        pausedResult = `0x${'1'.padStart(64, '0')}`;
        const paused = await mod.validateTempoFeeToken({
          rpcUrl: 'https://rpc.example',
          feeToken,
        });
        let invalidChainId = '';
        try {
          mod.buildTempoSetUserTokenRequest({
            chainId: 0,
            feeToken,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 1n,
          });
        } catch (error: unknown) {
          invalidChainId = error instanceof Error ? error.message : String(error);
        }
        let invalidGasLimit = '';
        try {
          mod.buildTempoSetUserTokenRequest({
            chainId: 1,
            feeToken,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 0n,
          });
        } catch (error: unknown) {
          invalidGasLimit = error instanceof Error ? error.message : String(error);
        }
        return { unsupported, paused, invalidChainId, invalidGasLimit };
      } finally {
        globalThis.fetch = originalFetch;
      }
    }, SDK_ESM_PATHS.advanced);

    expect(result.unsupported).toEqual({
      kind: 'invalid',
      feeToken: '0x20c0000000000000000000000000000000000001',
      reason: 'unsupported_currency',
      currency: 'EUR',
    });
    expect(result.paused).toEqual({
      kind: 'invalid',
      feeToken: '0x20c0000000000000000000000000000000000001',
      reason: 'paused',
      currency: 'USD',
    });
    expect(result.invalidChainId).toBe('[tempo] chainId must be a positive safe integer');
    expect(result.invalidGasLimit).toBe('[tempo] gasLimit must be positive');
  });
});

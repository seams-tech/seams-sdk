import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/sdk/esm/core/rpcClients/evm/publicClient.js' as const;

test.describe('evm public client waitForTransactionReceipt', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('waits for mined receipt via helper client', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmPublicClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
      };
      const txHash = `0x${'11'.repeat(32)}` as `0x${string}`;

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes('mock-rpc') || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }

        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');

        if (method === 'eth_getTransactionReceipt') {
          counters.receiptCalls += 1;
          const mined = counters.receiptCalls >= 2;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: mined
                ? {
                    blockNumber: '0x2',
                    status: '0x1',
                    gasUsed: '0x5208',
                  }
                : null,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }

        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `unexpected method: ${method}` },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      try {
        const client = createEvmPublicClient({ rpcUrl: 'https://mock-rpc' });
        const receipt = await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 5_000,
          pollIntervalMs: 5,
        });
        return {
          receipt,
          counters,
        };
      } finally {
        window.fetch = originalFetch;
      }
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThanOrEqual(2);
    expect(String(result.receipt?.blockNumber || '')).toBe('0x2');
    expect(String(result.receipt?.status || '')).toBe('0x1');
  });

  test('detects sustained underpriced pending tx via helper client', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmPublicClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        blockCalls: 0,
      };
      const txHash = `0x${'22'.repeat(32)}` as `0x${string}`;

      const originalFetch = window.fetch.bind(window);
      window.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url =
          typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        if (!url.includes('mock-rpc') || String(init?.method || 'GET').toUpperCase() !== 'POST') {
          return await originalFetch(input, init);
        }

        let body: Record<string, unknown> = {};
        try {
          body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        } catch {}
        const id = body.id ?? Date.now();
        const method = String(body.method || '');

        if (method === 'eth_getTransactionReceipt') {
          counters.receiptCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getBlockByNumber') {
          counters.blockCalls += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                number: '0x3',
                baseFeePerGas: '0x77359400',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }

        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `unexpected method: ${method}` },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }) as typeof fetch;

      let errorMessage = '';
      try {
        const client = createEvmPublicClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 120,
          pollIntervalMs: 5,
          maxFeePerGasHint: 1_000_000_000n,
        });
      } catch (error: unknown) {
        errorMessage = error instanceof Error ? error.message : String(error);
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorMessage,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.blockCalls).toBeGreaterThan(0);
    expect(result.errorMessage).toContain('underpriced fees');
  });
});

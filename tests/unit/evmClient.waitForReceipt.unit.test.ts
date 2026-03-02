import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/sdk/esm/core/rpcClients/evm/EvmClient.js' as const;

test.describe('evm client waitForTransactionReceipt', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('waits for mined receipt via helper client', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
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
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
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
      const { createEvmClient } = await import(importPath);
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
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
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

  test('waits for required confirmation depth via helper client', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        blockCalls: 0,
      };
      const txHash = `0x${'33'.repeat(32)}` as `0x${string}`;

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
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                blockNumber: '0x2',
                status: '0x1',
                gasUsed: '0x5208',
              },
            }),
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
                number: counters.blockCalls >= 2 ? '0x3' : '0x2',
                baseFeePerGas: '0x3b9aca00',
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

      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        const receipt = await client.waitForTransactionReceipt({
          txHash,
          confirmations: 2,
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
    expect(result.counters.blockCalls).toBeGreaterThanOrEqual(2);
    expect(String(result.receipt?.blockNumber || '')).toBe('0x2');
  });

  test('detects dropped or replaced tx when account nonce advances past tx nonce', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'44'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'55'.repeat(20)}` as `0x${string}`;

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
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          const result =
            counters.txCalls === 1
              ? {
                  from: sender,
                  nonce: '0x7',
                  blockNumber: null,
                }
              : null;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: '0x9',
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
      let errorCode = '';
      let errorReason = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 2_000,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        const maybeError = error as { message?: string; code?: string; reason?: string };
        errorMessage = String(maybeError?.message || error || '');
        errorCode = String(maybeError?.code || '');
        errorReason = String(maybeError?.reason || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorMessage,
        errorCode,
        errorReason,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(0);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.errorReason).toBe('dropped');
    expect(result.errorMessage).toContain('dropped or replaced');
  });

  test('detects dropped tx when hash disappears after being observed and nonce does not advance', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'98'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'34'.repeat(20)}` as `0x${string}`;

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
        const params = (Array.isArray(body.params) ? body.params : []) as unknown[];

        if (method === 'eth_getTransactionReceipt') {
          counters.receiptCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          const result =
            counters.txCalls === 1
              ? {
                  from: sender,
                  nonce: '0x7',
                  blockNumber: null,
                }
              : null;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          const blockTag = String(params[1] || 'latest');
          const result = blockTag === 'pending' ? '0x7' : '0x7';
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
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

      let errorCode = '';
      let errorMessage = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 2_000,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
        errorMessage = String((error as { message?: unknown })?.message || error || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorCode,
        errorMessage,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(1);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.errorMessage).toContain('dropped or replaced');
  });

  test('detects dropped tx when hash is never observed and nonce does not progress', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'8c'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'21'.repeat(20)}` as `0x${string}`;

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
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: '0x7' }),
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

      let errorCode = '';
      let errorMessage = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          senderHint: sender,
          nonceHint: 7n,
          timeoutMs: 500,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
        errorMessage = String((error as { message?: unknown })?.message || error || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorCode,
        errorMessage,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(0);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.errorMessage).toContain('never became visible');
  });

  test('classifies replaced when hash disappears and pending nonce moves ahead', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'ab'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'56'.repeat(20)}` as `0x${string}`;

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
        const params = (Array.isArray(body.params) ? body.params : []) as unknown[];

        if (method === 'eth_getTransactionReceipt') {
          counters.receiptCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          const result =
            counters.txCalls === 1
              ? {
                  from: sender,
                  nonce: '0x7',
                  blockNumber: null,
                }
              : null;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          const blockTag = String(params[1] || 'latest');
          const result = blockTag === 'pending' ? '0x8' : '0x7';
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
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

      let errorCode = '';
      let errorReason = '';
      let errorMessage = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 500,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
        errorReason = String((error as { reason?: unknown })?.reason || '');
        errorMessage = String((error as { message?: unknown })?.message || error || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorCode,
        errorReason,
        errorMessage,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(1);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.errorReason).toBe('replaced');
    expect(result.errorMessage).toContain('pending nonce moved ahead');
  });

  test('does not classify replaced when hash flickers but reappears before threshold', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'bc'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'67'.repeat(20)}` as `0x${string}`;

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
        const params = (Array.isArray(body.params) ? body.params : []) as unknown[];

        if (method === 'eth_getTransactionReceipt') {
          counters.receiptCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          const result =
            counters.txCalls % 2 === 1
              ? {
                  from: sender,
                  nonce: '0x7',
                  blockNumber: null,
                }
              : null;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          const blockTag = String(params[1] || 'latest');
          const result = blockTag === 'pending' ? '0x8' : '0x7';
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result }),
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

      let errorCode = '';
      let errorMessage = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          timeoutMs: 120,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
        errorMessage = String((error as { message?: unknown })?.message || error || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorCode,
        errorMessage,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(1);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('');
    expect(result.errorMessage).toContain('Timed out waiting for tx receipt');
  });

  test('does not classify as dropped when tx is already mined but receipt indexing lags', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'aa'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'bb'.repeat(20)}` as `0x${string}`;

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
          const mined = counters.receiptCalls >= 3;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: mined
                ? {
                    blockNumber: '0x21',
                    status: '0x1',
                    gasUsed: '0x5208',
                  }
                : null,
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                from: sender,
                nonce: '0x7',
                blockNumber: '0x21',
              },
            }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: '0x8',
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

      let receiptBlockNumber = '';
      let errorCode = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        const receipt = await client.waitForTransactionReceipt({
          txHash,
          senderHint: sender,
          nonceHint: 7n,
          timeoutMs: 5_000,
          pollIntervalMs: 5,
        });
        receiptBlockNumber = String(receipt?.blockNumber || '');
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        receiptBlockNumber,
        errorCode,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThanOrEqual(3);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('');
    expect(result.receiptBlockNumber).toBe('0x21');
  });

  test('uses nonce hints to detect dropped tx when tx-by-hash is unavailable', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { createEvmClient } = await import(importPath);
      const counters = {
        receiptCalls: 0,
        txCalls: 0,
        txCountCalls: 0,
      };
      const txHash = `0x${'66'.repeat(32)}` as `0x${string}`;
      const sender = `0x${'77'.repeat(20)}` as `0x${string}`;

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
        if (method === 'eth_getTransactionByHash') {
          counters.txCalls += 1;
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          counters.txCountCalls += 1;
          return new Response(
            JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: '0x6',
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

      let errorCode = '';
      try {
        const client = createEvmClient({ rpcUrl: 'https://mock-rpc' });
        await client.waitForTransactionReceipt({
          txHash,
          senderHint: sender,
          nonceHint: 5n,
          timeoutMs: 2_000,
          pollIntervalMs: 5,
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: unknown })?.code || '');
      } finally {
        window.fetch = originalFetch;
      }

      return {
        counters,
        errorCode,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.counters.receiptCalls).toBeGreaterThan(0);
    expect(result.counters.txCountCalls).toBeGreaterThan(0);
    expect(result.counters.txCalls).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
  });
});

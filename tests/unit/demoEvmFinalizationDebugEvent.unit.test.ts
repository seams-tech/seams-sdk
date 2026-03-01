import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATH = '/src/flows/demo/demoEvmHelpers.ts' as const;

test.describe('demo EVM finalization debug event payload', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('emits enriched dropped/replaced metadata for debug diagnostics', async ({ page }) => {
    const result = await page.evaluate(async ({ importPath }) => {
      const { waitForEvmTransactionFinalization } = await import(importPath);
      const txHash = `0x${'88'.repeat(32)}` as `0x${string}`;
      const senderHint = `0x${'12'.repeat(20)}` as `0x${string}`;
      const events: any[] = [];

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
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionByHash') {
          return new Response(
            JSON.stringify({ jsonrpc: '2.0', id, result: null }),
            { status: 200, headers: { 'content-type': 'application/json' } },
          );
        }
        if (method === 'eth_getTransactionCount') {
          const blockTag = Array.isArray(body.params) ? String(body.params[1] || '') : '';
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
      try {
        await waitForEvmTransactionFinalization({
          rpcUrl: 'https://mock-rpc',
          txHash,
          chain: 'tempo',
          chainId: 42431,
          senderHint,
          nonceHint: 7n,
          timeoutMs: 500,
          pollIntervalMs: 5,
          onFinalizationDebugEvent: (event) => {
            events.push(event);
          },
        });
      } catch (error: unknown) {
        errorCode = String((error as { code?: string })?.code || '');
        errorReason = String((error as { reason?: string })?.reason || '');
      } finally {
        window.fetch = originalFetch;
      }

      const event = events[events.length - 1] || null;
      return {
        event,
        errorCode,
        errorReason,
        emittedCount: events.length,
      };
    }, { importPath: IMPORT_PATH });

    expect(result.emittedCount).toBeGreaterThan(0);
    expect(result.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.errorReason).toBe('replaced');
    expect(result.event).toBeTruthy();
    expect(result.event.branch).toBe('dropped_hash_disappeared');
    expect(result.event.chain).toBe('tempo');
    expect(result.event.chainId).toBe(42431);
    expect(String(result.event.sender || '').toLowerCase()).toBe(`0x${'12'.repeat(20)}`);
    expect(result.event.nonce).toBe('7');
    expect(result.event.errorCode).toBe('tx_dropped_or_replaced');
    expect(result.event.reason).toBe('replaced');
  });
});

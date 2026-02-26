import { test, expect } from '@playwright/test';

test.describe('signer worker runtime boundary', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/', { waitUntil: 'domcontentloaded' });
  });

  test('accepts requests without version fields and preserves typed signer errors', async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      const { requestWorkerOperation } =
        await import('/sdk/esm/core/signingEngine/workerManager/workerTransport.js');

      try {
        await requestWorkerOperation({
          kind: 'tempoSigner',
          request: {
            type: 'computeTempoSenderHash',
            payload: { tx: {} },
          },
        } as any);
        return { ok: true as const };
      } catch (error: any) {
        return {
          ok: false as const,
          name: error?.name || '',
          code: error?.code || '',
          coreCode: error?.coreCode || '',
          message: error?.message || String(error),
        };
      }
    });

    expect(result.ok).toBe(false);
    expect((result as any).name).toBe('SignerWorkerOperationError');
    expect((result as any).code).toBe('SIGNER_INVALID_INPUT');
    expect((result as any).coreCode).toBe('InvalidInput');
  });
});

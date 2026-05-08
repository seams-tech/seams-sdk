import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  registry: '/sdk/esm/core/signingEngine/uiConfirm/confirmationReadinessRegistry.js',
} as const;

test.describe('confirmation readiness registry', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('consume returns readiness once and clears the entry', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const registry = await import(paths.registry);
        const requestId = `consume-${Date.now()}-${Math.random()}`;
        registry.registerConfirmationReadiness({
          requestId,
          readiness: {
            promise: Promise.resolve('ready'),
            body: 'Preparing signer',
          },
        });

        const first = registry.consumeConfirmationReadiness(requestId);
        const second = registry.consumeConfirmationReadiness(requestId);
        const resolved = first ? await first.promise : null;
        return {
          firstBody: first?.body ?? null,
          resolved,
          secondMissing: second == null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      firstBody: 'Preparing signer',
      resolved: 'ready',
      secondMissing: true,
    });
  });

  test('clear removes readiness before it is consumed', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const registry = await import(paths.registry);
        const requestId = `clear-${Date.now()}-${Math.random()}`;
        registry.registerConfirmationReadiness({
          requestId,
          readiness: {
            promise: Promise.resolve('ready'),
            body: 'Preparing signer',
          },
        });
        registry.clearConfirmationReadiness(requestId);
        return registry.consumeConfirmationReadiness(requestId) == null;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toBe(true);
  });

  test('ttl clears abandoned readiness entries', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const registry = await import(paths.registry);
        const requestId = `ttl-${Date.now()}-${Math.random()}`;
        registry.registerConfirmationReadiness({
          requestId,
        ttlMs: 50,
          readiness: {
            promise: Promise.resolve('ready'),
            body: 'Preparing signer',
          },
        });
      await new Promise((resolve) => setTimeout(resolve, 250));
        return registry.consumeConfirmationReadiness(requestId) == null;
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toBe(true);
  });

  test('concurrent request ids do not consume each other', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const registry = await import(paths.registry);
        const requestIdA = `concurrent-a-${Date.now()}-${Math.random()}`;
        const requestIdB = `concurrent-b-${Date.now()}-${Math.random()}`;
        registry.registerConfirmationReadiness({
          requestId: requestIdA,
          readiness: {
            promise: Promise.resolve('a'),
            body: 'Preparing A',
          },
        });
        registry.registerConfirmationReadiness({
          requestId: requestIdB,
          readiness: {
            promise: Promise.resolve('b'),
            body: 'Preparing B',
          },
        });

        const first = registry.consumeConfirmationReadiness(requestIdA);
        const second = registry.consumeConfirmationReadiness(requestIdB);
        return {
          firstBody: first?.body ?? null,
          firstResolved: first ? await first.promise : null,
          secondBody: second?.body ?? null,
          secondResolved: second ? await second.promise : null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      firstBody: 'Preparing A',
      firstResolved: 'a',
      secondBody: 'Preparing B',
      secondResolved: 'b',
    });
  });
});

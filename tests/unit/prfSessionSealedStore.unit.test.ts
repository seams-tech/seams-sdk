import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  prfSessionSealedStore: '/sdk/esm/core/signingEngine/api/session/prfSessionSealedStore.js',
} as const;

test.describe('PRF session sealed store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('writes shamir3pass records without persisting plaintext PRF', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.prfSessionSealedStore);
        const thresholdSessionId = 'sess-sealed-1';
        mod.clearAllPrfSessionSealedRecords();
        mod.writePrfSessionSealedRecord({
          thresholdSessionId,
          sealedPrfFirstB64u: 'sealed-prf-b64u',
          keyVersion: 'kek-s-2026-02',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: Date.now(),
        });

        const record = mod.readPrfSessionSealedRecord(thresholdSessionId);
        const raw = sessionStorage.getItem(`tatchi:threshold-prf-sealed:v1:${thresholdSessionId}`);
        const parsedRaw = raw ? JSON.parse(raw) : null;
        const indexRaw = sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index');
        const index = indexRaw ? JSON.parse(indexRaw) : [];
        return {
          record,
          index,
          rawHasPlaintextPrf: !!parsedRaw && Object.prototype.hasOwnProperty.call(parsedRaw, 'prfFirstB64u'),
          rawAlg: parsedRaw?.alg ?? null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.record?.alg).toBe('shamir3pass-v1');
    expect(result.record?.sealedPrfFirstB64u).toBe('sealed-prf-b64u');
    expect(result.record?.keyVersion).toBe('kek-s-2026-02');
    expect(result.index).toEqual(['sess-sealed-1']);
    expect(result.rawHasPlaintextPrf).toBe(false);
    expect(result.rawAlg).toBe('shamir3pass-v1');
  });

  test('fails closed on malformed/legacy record payloads', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.prfSessionSealedStore);
        const thresholdSessionId = 'sess-legacy';
        sessionStorage.setItem(
          `tatchi:threshold-prf-sealed:v1:${thresholdSessionId}`,
          JSON.stringify({
            v: 1,
            alg: 'plain-v1',
            thresholdSessionId,
            prfFirstB64u: 'plaintext',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            updatedAtMs: Date.now(),
          }),
        );
        sessionStorage.setItem('tatchi:threshold-prf-sealed:v1:index', JSON.stringify([thresholdSessionId]));

        const read = mod.readPrfSessionSealedRecord(thresholdSessionId);
        mod.deletePrfSessionSealedRecord(thresholdSessionId);
        const indexAfterDeleteRaw = sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index');
        const indexAfterDelete = indexAfterDeleteRaw ? JSON.parse(indexAfterDeleteRaw) : [];

        return {
          read,
          indexAfterDelete,
          rawAfterDelete: sessionStorage.getItem(`tatchi:threshold-prf-sealed:v1:${thresholdSessionId}`),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.read).toBeNull();
    expect(result.indexAfterDelete).toEqual([]);
    expect(result.rawAfterDelete).toBeNull();
  });

  test('clearAll removes all sealed records and index', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.prfSessionSealedStore);
        mod.writePrfSessionSealedRecord({
          thresholdSessionId: 'sess-a',
          sealedPrfFirstB64u: 'a',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        mod.writePrfSessionSealedRecord({
          thresholdSessionId: 'sess-b',
          sealedPrfFirstB64u: 'b',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        const beforeRaw = sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index');
        const before = beforeRaw ? JSON.parse(beforeRaw) : [];
        mod.clearAllPrfSessionSealedRecords();
        const afterRaw = sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index');
        const after = afterRaw ? JSON.parse(afterRaw) : [];
        return {
          before,
          after,
          indexAfter: sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.before).toEqual(['sess-a', 'sess-b']);
    expect(result.after).toEqual([]);
    expect(result.indexAfter).toBeNull();
  });

  test('uses localStorage in wallet iframe host mode for reload continuity', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean }).__W3A_TEST_WALLET_IFRAME_HOST_MODE__ =
          true;
        try {
          const mod = await import(paths.prfSessionSealedStore);
          const thresholdSessionId = 'sess-host-mode';
          mod.clearAllPrfSessionSealedRecords();
          mod.writePrfSessionSealedRecord({
            thresholdSessionId,
            sealedPrfFirstB64u: 'sealed-host',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 2,
            updatedAtMs: Date.now(),
          });
          return {
            localRaw: localStorage.getItem(`tatchi:threshold-prf-sealed:v1:${thresholdSessionId}`),
            sessionRaw: sessionStorage.getItem(
              `tatchi:threshold-prf-sealed:v1:${thresholdSessionId}`,
            ),
            localIndex: localStorage.getItem('tatchi:threshold-prf-sealed:v1:index'),
            sessionIndex: sessionStorage.getItem('tatchi:threshold-prf-sealed:v1:index'),
          };
        } finally {
          delete (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean })
            .__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
          localStorage.removeItem('tatchi:threshold-prf-sealed:v1:sess-host-mode');
          localStorage.removeItem('tatchi:threshold-prf-sealed:v1:index');
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.localRaw).not.toBeNull();
    expect(result.localIndex).toBe(JSON.stringify(['sess-host-mode']));
    expect(result.sessionRaw).toBeNull();
    expect(result.sessionIndex).toBeNull();
  });
});

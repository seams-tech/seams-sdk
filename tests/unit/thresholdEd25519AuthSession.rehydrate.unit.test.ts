import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/session/persistence/records.js',
} as const;

test.describe('threshold Ed25519 auth-session rehydrate', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('keeps canonical Ed25519 session records out of sessionStorage for wallet host mode', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean }).__W3A_TEST_WALLET_IFRAME_HOST_MODE__ =
          true;
        try {
          const storeMod = await import(paths.thresholdSessionStore);
          storeMod.clearAllStoredThresholdEd25519SessionRecords();
          storeMod.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            relayerUrl: 'https://relay.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'tsess-host-mode',
            thresholdSessionAuthToken: 'jwt-host-mode',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });
          const record = storeMod.getStoredThresholdEd25519SessionRecordForAccount(
            'alice.testnet',
          );
          return {
            record,
            localRecord: localStorage.getItem('seams:threshold-ed25519-session:v1:alice.testnet'),
            localIndex: localStorage.getItem('seams:threshold-ed25519-session:v1:index'),
            localSessionIndex: localStorage.getItem(
              'seams:threshold-ed25519-session:v1:session-index',
            ),
            sessionRecord: sessionStorage.getItem(
              'seams:threshold-ed25519-session:v1:alice.testnet',
            ),
            sessionIndex: sessionStorage.getItem('seams:threshold-ed25519-session:v1:index'),
            sessionSessionIndex: sessionStorage.getItem(
              'seams:threshold-ed25519-session:v1:session-index',
            ),
          };
        } finally {
          delete (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean })
            .__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
          sessionStorage.removeItem('seams:threshold-ed25519-session:v1:alice.testnet');
          sessionStorage.removeItem('seams:threshold-ed25519-session:v1:index');
          sessionStorage.removeItem('seams:threshold-ed25519-session:v1:session-index');
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.localRecord).toBeNull();
    expect(result.localIndex).toBeNull();
    expect(result.localSessionIndex).toBeNull();
    expect(result.sessionRecord).toBeNull();
    expect(result.sessionIndex).toBeNull();
    expect(result.sessionSessionIndex).toBeNull();
    expect(result.record?.thresholdSessionId).toBe('tsess-host-mode');
  });
});

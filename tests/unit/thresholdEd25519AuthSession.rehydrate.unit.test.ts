import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
} as const;

test.describe('threshold Ed25519 auth-session rehydrate', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('stores canonical Ed25519 session records in sessionStorage for wallet host mode', async ({
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
            thresholdSessionJwt: 'jwt-host-mode',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            source: 'login',
          });
          return {
            localRecord: localStorage.getItem('tatchi:threshold-ed25519-session:v1:alice.testnet'),
            localIndex: localStorage.getItem('tatchi:threshold-ed25519-session:v1:index'),
            localSessionIndex: localStorage.getItem(
              'tatchi:threshold-ed25519-session:v1:session-index',
            ),
            sessionRecord: sessionStorage.getItem(
              'tatchi:threshold-ed25519-session:v1:alice.testnet',
            ),
            sessionIndex: sessionStorage.getItem('tatchi:threshold-ed25519-session:v1:index'),
            sessionSessionIndex: sessionStorage.getItem(
              'tatchi:threshold-ed25519-session:v1:session-index',
            ),
          };
        } finally {
          delete (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean })
            .__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
          sessionStorage.removeItem('tatchi:threshold-ed25519-session:v1:alice.testnet');
          sessionStorage.removeItem('tatchi:threshold-ed25519-session:v1:index');
          sessionStorage.removeItem('tatchi:threshold-ed25519-session:v1:session-index');
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.localRecord).toBeNull();
    expect(result.localIndex).toBeNull();
    expect(result.localSessionIndex).toBeNull();
    expect(result.sessionRecord).not.toBeNull();
    expect(result.sessionIndex).toBe(JSON.stringify(['alice.testnet']));
    expect(result.sessionSessionIndex).toContain('tsess-host-mode');
  });
});

/**
 * Threshold Ed25519 (2-party) — registration bootstrap integrity.
 *
 * Validates that the client rejects a tampered `registration/bootstrap` response when the returned
 * operational key no longer matches the on-chain key set created during bootstrap.
 */

import { test, expect } from '@playwright/test';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  installFastNearRpcMock,
  installThresholdEd25519RegistrationMocks,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';

test.describe('threshold-ed25519 bootstrap integrity', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('rejects tampered bootstrap operational publicKey', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();

    const attackerPublicKey = `ed25519:${bs58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(7)))}`;

    await installThresholdEd25519RegistrationMocks(page, {
      relayerBaseUrl: 'http://localhost:3000',
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
      mutateThresholdEd25519Response: (thresholdEd25519) => ({
        ...thresholdEd25519,
        publicKey: attackerPublicKey,
      }),
    });

    await installFastNearRpcMock(page, {
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
      strictAccessKeyLookup: true,
    });

    const result = await page.evaluate(async () => {
      try {
        const { TatchiPasskey } = await import('/sdk/esm/core/TatchiPasskey/index.js');
        const suffix =
          typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
        const accountId = `e2ebootstrap${suffix}.w3a-v1.testnet`;

        const pm = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayer: { url: 'http://localhost:3000' },
          iframeWallet: { walletOrigin: '' },
        });

        const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };
        const reg = await pm.registration.registerPasskeyInternal(
          accountId,
          {
            signerOptions: {
              tempo: {
                enabled: false,
                participantIds: [1, 2],
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
              evm: {
                enabled: false,
                participantIds: [1, 2],
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
            },
          },
          confirmConfig as any,
        );
        return { success: !!reg?.success, error: String(reg?.error || '') };
      } catch (e: any) {
        return { success: false, error: e?.message || String(e) };
      }
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('Bootstrap verification failed');
  });
});

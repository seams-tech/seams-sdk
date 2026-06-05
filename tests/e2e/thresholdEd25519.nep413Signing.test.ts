/**
 * Threshold Ed25519 (2-party) — NEP-413 message signing.
 *
 * Validates that the relayer-assisted signing flow produces a NEP-413 signature that verifies under
 * the threshold public key and not under an unrelated Ed25519 key.
 */

import { test, expect } from '@playwright/test';
import bs58 from 'bs58';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';
import { threshold_ed25519_compute_nep413_signing_digest } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

test.describe('threshold-ed25519 NEP-413 signing', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('happy path: threshold NEP-413 signature verifies under threshold key', async ({ page }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();
    const managedRegistrationHarness = await setupManagedThresholdRegistrationHarness({
      page,
      service,
      threshold,
      keyName: 'threshold-nep413-browser',
      orgId: 'org_threshold_nep413',
      orgSlug: 'threshold-nep413-org',
      orgName: 'Threshold NEP-413 Org',
      projectId: 'proj_threshold_nep413',
      projectName: 'Threshold NEP-413 Project',
    });

    try {
      await installCreateAccountAndRegisterUserMock(page, {
        relayerBaseUrl: managedRegistrationHarness.baseUrl,
        keysOnChain,
        nonceByPublicKey,
        accountsOnChain,
        onNewPublicKey: (publicKey) => {
          keysOnChain.add(publicKey);
          nonceByPublicKey.set(publicKey, nonceByPublicKey.get(publicKey) ?? 0);
        },
        onNewAccountId: (accountId) => {
          accountsOnChain.add(accountId);
        },
        session: managedRegistrationHarness.session,
        runtimePolicyScope: managedRegistrationHarness.runtimePolicyScope,
      });

      await installFastNearRpcMock(page, {
        keysOnChain,
        nonceByPublicKey,
        strictAccessKeyLookup: true,
        accountsOnChain,
      });

      const result = await page.evaluate(
        async ({ relayerUrl, managedRegistration }) => {
          try {
            const { SeamsWeb } = await import('/sdk/esm/SeamsWeb/index.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2enep413${suffix}.w3a-v1.testnet`;

            const pm = new SeamsWeb({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayer: { url: relayerUrl },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: { walletOrigin: '' },
            });

            const confirmConfig = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };

            const reg = await pm.registration.registerPasskey(accountId, {
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
              confirmationConfig: confirmConfig as any,
            });
            if (!reg?.success) return { ok: false, error: reg?.error || 'registration failed' };

            const login = await pm.auth.unlock(accountId);
            if (!login?.success) return { ok: false, error: login?.error || 'login failed' };

            const operationalPublicKey = String(reg.operationalPublicKey || '');
            const message = 'hello threshold nep413';
            const recipient = 'example.localhost';
            const state = 'test-state';
            const signed = await pm.near.signNEP413Message({
              nearAccount: { accountId },
              params: { message, recipient, state },
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });
            if (!signed?.success)
              return { ok: false, error: signed?.error || 'nep413 signing failed' };
            return {
              ok: true,
              accountId,
              message,
              recipient,
              state,
              nonce: String((signed as any)?.nonce || ''),
              operationalPublicKey,
              signerPublicKey: String(signed.publicKey || ''),
              signature: String(signed.signature || ''),
            };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        {
          relayerUrl: managedRegistrationHarness.baseUrl,
          managedRegistration: managedRegistrationHarness.managedRegistration,
        },
      );

      if (!result.ok) {
        throw new Error(`nep413 threshold signing test failed: ${result.error || 'unknown'}`);
      }

      expect(String(result.operationalPublicKey)).toMatch(/^ed25519:/);
      expect(String(result.signerPublicKey)).toBe(String(result.operationalPublicKey));

      const toPkBytes = (pk: string): Uint8Array => {
        const raw = pk.includes(':') ? pk.split(':')[1] : pk;
        return bs58.decode(raw);
      };
      const wrongPublicKey = `ed25519:${bs58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(44)))}`;
      const sigStr = String(result.signature || '');
      const sigBytes = Uint8Array.from(
        Buffer.from(sigStr, sigStr.includes('-') || sigStr.includes('_') ? 'base64url' : 'base64'),
      );
      expect(sigBytes.length).toBe(64);

      const signingPayload = {
        kind: 'nep413',
        nearAccountId: String(result.accountId),
        message: String(result.message),
        recipient: String(result.recipient),
        nonce: String(result.nonce),
        state: String(result.state),
      };

      const digestUnknown: unknown =
        threshold_ed25519_compute_nep413_signing_digest(signingPayload);
      const digest = digestUnknown instanceof Uint8Array ? digestUnknown : null;
      if (!digest || digest.length !== 32) {
        throw new Error('Expected NEP-413 signing digest to be a 32-byte Uint8Array');
      }

      expect(ed25519.verify(sigBytes, digest, toPkBytes(String(result.operationalPublicKey)))).toBe(
        true,
      );
      expect(ed25519.verify(sigBytes, digest, toPkBytes(wrongPublicKey))).toBe(false);
    } finally {
      await managedRegistrationHarness.close().catch(() => undefined);
    }
  });
});

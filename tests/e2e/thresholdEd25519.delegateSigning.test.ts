/**
 * Threshold Ed25519 (2-party) — delegate action signing (NEP-461).
 *
 * Validates that the relayer-assisted 2-round signing flow produces a signature that verifies under
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
import { threshold_ed25519_compute_delegate_signing_digest } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

test.describe('threshold-ed25519 delegate signing (NEP-461)', () => {
  test.setTimeout(180_000);

  test.beforeEach(async ({ page }) => {
    await setupThresholdE2ePage(page);
  });

  test('happy path: threshold delegate signature verifies under threshold key', async ({
    page,
  }) => {
    const keysOnChain = new Set<string>();
    const nonceByPublicKey = new Map<string, number>();
    const accountsOnChain = new Set<string>();

    const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
    await service.getRelayerAccount();
    const managedRegistrationHarness = await setupManagedThresholdRegistrationHarness({
      page,
      service,
      threshold,
      keyName: 'threshold-delegate-browser',
      orgId: 'org_threshold_delegate',
      orgSlug: 'threshold-delegate-org',
      orgName: 'Threshold Delegate Org',
      projectId: 'proj_threshold_delegate',
      projectName: 'Threshold Delegate Project',
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

      type DelegateSigningResult =
        | {
            ok: true;
            accountId: string;
            operationalPublicKey: string;
            signingPayload: unknown;
            signature: number[];
          }
        | { ok: false; error: string };

      const result = (await page.evaluate(
        async ({ relayerUrl, managedRegistration }) => {
          try {
            const { SeamsWeb } = await import('/sdk/esm/web/SeamsWeb/index.js');
            const { ActionType, toActionArgsWasm } = await import('/sdk/esm/core/types/actions.js');
            const suffix =
              typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? crypto.randomUUID()
                : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            const accountId = `e2edelegate${suffix}.w3a-v1.testnet`;

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

            const actions = [{ type: ActionType.Transfer, amount: '1' }];
            const wasmActions = actions.map(toActionArgsWasm);
            const delegate = {
              senderId: accountId,
              receiverId: 'w3a-v1.testnet',
              actions,
              nonce: 1,
              maxBlockHeight: 999_999,
              publicKey: operationalPublicKey,
            };

            const signed = await pm.near.signDelegateAction({
              nearAccount: { accountId },
              delegate,
              options: {
                confirmationConfig: confirmConfig as any,
              },
            });

            const sd = signed?.signedDelegate as any;
            const da = sd?.delegateAction as any;
            const signedNonce =
              typeof da?.nonce === 'bigint' ? da.nonce.toString() : String(da?.nonce || '');
            const signedMaxBlockHeight =
              typeof da?.maxBlockHeight === 'bigint'
                ? da.maxBlockHeight.toString()
                : String(da?.maxBlockHeight || '');
            const sigData = sd?.signature?.signatureData;
            const sigBytes =
              sigData instanceof Uint8Array
                ? Array.from(sigData)
                : Array.isArray(sigData)
                  ? sigData.map((n) => Number(n))
                  : null;
            if (!sigBytes || sigBytes.length !== 64) {
              return { ok: false, error: 'missing signature bytes' };
            }

            return {
              ok: true,
              accountId,
              operationalPublicKey,
              signingPayload: {
                kind: 'nep461_delegate',
                delegate: {
                  senderId: accountId,
                  receiverId: delegate.receiverId,
                  actions: wasmActions,
                  nonce: signedNonce || String(delegate.nonce),
                  maxBlockHeight: signedMaxBlockHeight || String(delegate.maxBlockHeight),
                  publicKey: operationalPublicKey,
                },
              },
              signature: sigBytes,
            };
          } catch (e: any) {
            return { ok: false, error: e?.message || String(e) };
          }
        },
        {
          relayerUrl: managedRegistrationHarness.baseUrl,
          managedRegistration: managedRegistrationHarness.managedRegistration,
        },
      )) as DelegateSigningResult;

      if (!result.ok) {
        throw new Error(`delegate threshold signing test failed: ${result.error || 'unknown'}`);
      }

      const toPkBytes = (pk: string): Uint8Array => {
        const raw = pk.includes(':') ? pk.split(':')[1] : pk;
        return bs58.decode(raw);
      };
      const wrongPublicKey = `ed25519:${bs58.encode(ed25519.getPublicKey(new Uint8Array(32).fill(41)))}`;

      const digestUnknown: unknown = threshold_ed25519_compute_delegate_signing_digest(
        result.signingPayload,
      );
      const digest = digestUnknown instanceof Uint8Array ? digestUnknown : null;
      if (!digest || digest.length !== 32) {
        throw new Error('Expected delegate signing digest to be a 32-byte Uint8Array');
      }

      const sigBytes = Uint8Array.from(result.signature);
      expect(sigBytes.length).toBe(64);

      expect(ed25519.verify(sigBytes, digest, toPkBytes(String(result.operationalPublicKey)))).toBe(
        true,
      );
      expect(ed25519.verify(sigBytes, digest, toPkBytes(wrongPublicKey))).toBe(false);
    } finally {
      await managedRegistrationHarness.close().catch(() => undefined);
    }
  });
});

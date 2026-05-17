import { expect, test } from '@playwright/test';
import { setupThresholdEcdsaTempoHarness } from '../helpers/thresholdEcdsaTempoFlow';

test.describe('threshold-ecdsa link-device manual-bootstrap', () => {
  test.setTimeout(180_000);

  test('prepared link-device manual-bootstrap one-key session can sign then export', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { persistLinkDeviceThresholdEcdsaBootstrap } =
              await import('/sdk/esm/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `linkdeviceecdsa${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            pm.setConfirmationConfig(confirmationConfig as any);

            const registration = await pm.registration.registerPasskeyInternal(
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
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                stage: 'registration',
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const login = await pm.auth.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                stage: 'login',
                error: String(login?.error || 'unlock failed'),
              };
            }

            const bootstrap = await pm.tempo.bootstrapEcdsaSession({
              kind: 'reuse_warm_ecdsa_bootstrap',
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              subjectId: accountId,
              chainTarget: {
                kind: 'tempo' as const,
                chainId: 42431,
                networkSlug: 'tempo-testnet',
              },
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 10,
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId || !bootstrap?.keygen?.ok) {
              return {
                ok: false,
                stage: 'bootstrap',
                error: 'threshold ECDSA bootstrap did not return canonical one-key material',
              };
            }

            const participantIds =
              bootstrap.keygen?.participantIds ||
              bootstrap.thresholdEcdsaKeyRef?.participantIds ||
              undefined;
            const manualBootstrap = {
              ecdsaThresholdKeyId: String(bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || ''),
              signingRootId: String(bootstrap.thresholdEcdsaKeyRef.signingRootId || ''),
              signingRootVersion: String(bootstrap.thresholdEcdsaKeyRef.signingRootVersion || ''),
              clientVerifyingShareB64u: String(bootstrap.keygen?.clientVerifyingShareB64u || ''),
              clientAdditiveShare32B64u: String(bootstrap.keygen?.clientAdditiveShare32B64u || ''),
              relayerKeyId: String(bootstrap.keygen?.relayerKeyId || ''),
              thresholdEcdsaPublicKeyB64u: String(
                bootstrap.keygen?.thresholdEcdsaPublicKeyB64u || '',
              ),
              ethereumAddress: String(bootstrap.keygen?.ethereumAddress || ''),
              relayerVerifyingShareB64u: String(bootstrap.keygen?.relayerVerifyingShareB64u || ''),
              ...(Array.isArray(participantIds) ? { participantIds: [...participantIds] } : {}),
              session: {
                sessionKind: 'jwt',
                sessionId: String(bootstrap.session?.sessionId || ''),
                walletSigningSessionId: String(bootstrap.session?.walletSigningSessionId || ''),
                expiresAtMs: Number(bootstrap.session?.expiresAtMs || 0),
                ...(Array.isArray(participantIds) ? { participantIds: [...participantIds] } : {}),
                remainingUses: Number(bootstrap.session?.remainingUses || 0),
                jwt: String(bootstrap.session?.jwt || ''),
              },
            };

            await persistLinkDeviceThresholdEcdsaBootstrap({
              signingEngine: pm.getContext().signingEngine,
              walletId: accountId,
              relayerUrl,
              chainTarget: {
                kind: 'tempo' as const,
                chainId: 42431,
                networkSlug: 'tempo-testnet',
              },
              thresholdEcdsa: manualBootstrap,
            });

            const signingEngine = pm.getContext().signingEngine as any;
            const record = signingEngine.getThresholdEcdsaSessionRecordForSigning({
              nearAccountId: accountId,
              chain: 'tempo',
            });
            if (!record || record.source !== 'manual-bootstrap') {
              return {
                ok: false,
                stage: 'manual_bootstrap',
                error: `expected manual-bootstrap source, got ${String(record?.source || 'missing')}`,
              };
            }

            const signed = await pm.tempo.signTempo({
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              subjectId: accountId,
              chainTarget: {
                kind: 'tempo' as const,
                chainId: 42431,
                networkSlug: 'tempo-testnet',
              },
              request: {
                chain: 'tempo' as const,
                kind: 'tempoTransaction' as const,
                senderSignatureAlgorithm: 'secp256k1' as const,
                tx: {
                  chainId: 42431,
                  maxPriorityFeePerGas: 1n,
                  maxFeePerGas: 2n,
                  gasLimit: 21_000n,
                  calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n, input: '0x' }],
                  accessList: [],
                  nonceKey: 0n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' as const },
                  aaAuthorizationList: [],
                },
              },
              options: { confirmationConfig },
            });
            if (!signed || signed.kind !== 'tempoTransaction') {
              return {
                ok: false,
                stage: 'sign',
                error: 'tempo sign failed after link-device manual-bootstrap persistence',
              };
            }

            await pm.keys.exportKeypairWithUI({
              kind: 'ecdsa',
              subjectId: accountId,
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              chainTarget: {
                kind: 'tempo' as const,
                chainId: 42431,
                networkSlug: 'tempo-testnet',
              },
              options: {
                variant: 'modal',
              },
            });

            return {
              ok: true,
              source: String(record.source || ''),
              ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || ''),
              signedKind: String(signed.kind || ''),
              exportCompleted: true,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              stage: 'unexpected',
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.source).toBe('manual-bootstrap');
      expect(result.ecdsaThresholdKeyId).toBeTruthy();
      expect(result.signedKind).toBe('tempoTransaction');
      expect(result.exportCompleted).toBe(true);
    } finally {
      await harness.close();
    }
  });
});

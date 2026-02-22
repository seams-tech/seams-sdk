import { expect, test } from '@playwright/test';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';
import { corsHeadersForRoute } from './thresholdEd25519.testUtils';

test.describe('threshold-ecdsa tempo signing', () => {
  test.setTimeout(180_000);

  test('keygen -> connect session -> sign tempoTransaction', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.keygen?.relayerKeyId).toBeTruthy();
      expect(result.session?.ok).toBe(true);
      expect(result.session?.sessionId).toBeTruthy();
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      if (!result.signed || result.signed.kind !== 'tempoTransaction') {
        throw new Error('Expected tempoTransaction signed result');
      }
      expect(result.signed.senderHashHex.startsWith('0x')).toBeTruthy();
      expect(result.signed.rawTxHex.startsWith('0x')).toBeTruthy();
    } finally {
      await harness.close();
    }
  });

  test('rapid Tempo + EVM requests serialize without signing_in_progress', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(async ({ relayerUrl }) => {
        try {
          const sdkMod = await import('/sdk/esm/index.js');
          const { TatchiPasskey } = sdkMod as any;

          const accountId = `tempoqueue${Date.now()}.w3a-v1.testnet`;
          const confirmationConfig = {
            uiMode: 'none' as const,
            behavior: 'skipClick' as const,
            autoProceedDelay: 0,
          };

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            contractId: 'web3-authn-v4.testnet',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
              smartAccountDeploymentMode: 'observe',
            },
            iframeWallet: {
              walletOrigin: '',
              walletServicePath: '/wallet-service',
              sdkBasePath: '/sdk',
              rpIdOverride: 'example.localhost',
            },
          });

          const registration = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  sessionKind: 'jwt',
                  ttlMs: 1,
                  remainingUses: 1,
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  sessionKind: 'jwt',
                  ttlMs: 1,
                  remainingUses: 1,
                },
              },
            },
            confirmationConfig,
          );
          if (!registration?.success) {
            return {
              ok: false,
              error: String(registration?.error || 'registerPasskeyInternal failed'),
            };
          }

          const bootstrap = await pm.tempo.bootstrapEcdsaSession({
            nearAccountId: accountId,
            options: {
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
            },
          });
          if (!bootstrap?.session?.ok) {
            return {
              ok: false,
              error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
            };
          }

          const tempoRequest = {
            chain: 'tempo' as const,
            kind: 'tempoTransaction' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 42431n,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 0n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' as const },
              aaAuthorizationList: [],
            },
          };

          const evmRequest = {
            chain: 'evm' as const,
            kind: 'eip1559' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 11155111n,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          };

          const [tempoResult, evmResult] = await Promise.allSettled([
            pm.tempo.signTempo({
              nearAccountId: accountId,
              request: tempoRequest,
              options: { confirmationConfig },
            }),
            pm.tempo.signTempo({
              nearAccountId: accountId,
              request: evmRequest,
              options: { confirmationConfig },
            }),
          ]);

          const settled = [tempoResult, evmResult].map((entry, idx) => {
            if (entry.status === 'fulfilled') {
              return {
                index: idx,
                status: 'fulfilled' as const,
                chain: String(entry.value?.chain || ''),
                kind: String(entry.value?.kind || ''),
              };
            }
            return {
              index: idx,
              status: 'rejected' as const,
              error: String((entry.reason as any)?.message || entry.reason || ''),
            };
          });

          const rejectionMessages = settled
            .filter((entry) => entry.status === 'rejected')
            .map((entry) => String((entry as { error?: string }).error || ''));

          const containsInFlightMessage = rejectionMessages.some((message) =>
            /signing_in_progress|already in progress/i.test(message),
          );

          return {
            ok: rejectionMessages.length === 0 && !containsInFlightMessage,
            settled,
            rejectionMessages,
            containsInFlightMessage,
          };
        } catch (error: unknown) {
          return {
            ok: false,
            error: String(
              (error && typeof error === 'object' && 'message' in error)
                ? (error as { message?: unknown }).message
                : error || 'rapid threshold sign flow failed',
            ),
          };
        }
      }, { relayerUrl: harness.baseUrl });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.settled).toEqual([
        expect.objectContaining({
          index: 0,
          status: 'fulfilled',
          chain: 'tempo',
          kind: 'tempoTransaction',
        }),
        expect.objectContaining({
          index: 1,
          status: 'fulfilled',
          chain: 'evm',
          kind: 'eip1559',
        }),
      ]);
      expect(JSON.stringify(result.rejectionMessages || [])).not.toMatch(/signing_in_progress|already in progress/i);
    } finally {
      await harness.close();
    }
  });

  test('second request reaches confirmation before first settles under enforce deployment mode', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    let deployCalls = 0;
    try {
      await page.route(`${harness.baseUrl}/smart-account/deploy`, async (route) => {
        deployCalls += 1;
        if (deployCalls === 1) {
          await new Promise((resolve) => setTimeout(resolve, 900));
        }
        await route.fulfill({
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeadersForRoute(route),
          },
          body: JSON.stringify({
            ok: true,
            deploymentTxHash: `0xdeploy${deployCalls.toString(16).padStart(2, '0')}`,
          }),
        });
      });

      const result = await page.evaluate(async ({ relayerUrl }) => {
        try {
          const sdkMod = await import('/sdk/esm/index.js');
          const { TatchiPasskey } = sdkMod as any;

          const accountId = `tempoqueueenforce${Date.now()}.w3a-v1.testnet`;
          const confirmationConfig = {
            uiMode: 'none' as const,
            behavior: 'skipClick' as const,
            autoProceedDelay: 0,
          };

          const pm = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            contractId: 'web3-authn-v4.testnet',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
              smartAccountDeploymentMode: 'enforce',
            },
            iframeWallet: {
              walletOrigin: '',
              walletServicePath: '/wallet-service',
              sdkBasePath: '/sdk',
              rpIdOverride: 'example.localhost',
            },
          });

          const registration = await pm.registration.registerPasskeyInternal(
            accountId,
            {
              signerOptions: {
                tempo: {
                  enabled: false,
                  participantIds: [1, 2],
                  sessionKind: 'jwt',
                  ttlMs: 1,
                  remainingUses: 1,
                },
                evm: {
                  enabled: false,
                  participantIds: [1, 2],
                  sessionKind: 'jwt',
                  ttlMs: 1,
                  remainingUses: 1,
                },
              },
            },
            confirmationConfig,
          );
          if (!registration?.success) {
            return {
              ok: false,
              error: String(registration?.error || 'registerPasskeyInternal failed'),
            };
          }

          const bootstrap = await pm.tempo.bootstrapEcdsaSession({
            nearAccountId: accountId,
            options: {
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
            },
          });
          if (!bootstrap?.session?.ok) {
            return {
              ok: false,
              error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
            };
          }

          const tempoRequest = {
            chain: 'tempo' as const,
            kind: 'tempoTransaction' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 42431n,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 0n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' as const },
              aaAuthorizationList: [],
            },
          };

          const evmRequest = {
            chain: 'evm' as const,
            kind: 'eip1559' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 11155111n,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          };

          type ProgressEvent = {
            label: 'first' | 'second';
            phase: string;
            status: 'progress' | 'success' | 'error';
            atMs: number;
          };
          const progressEvents: ProgressEvent[] = [];
          const settledAtMs: Partial<Record<'first' | 'second', number>> = {};
          const startedAtMs = performance.now();

          const runSign = async (
            label: 'first' | 'second',
            request: typeof tempoRequest | typeof evmRequest,
          ) => {
            try {
              const value = await pm.tempo.signTempo({
                nearAccountId: accountId,
                request,
                options: {
                  confirmationConfig,
                  onEvent: (ev: {
                    phase?: unknown;
                    status?: unknown;
                  }) => {
                    progressEvents.push({
                      label,
                      phase: String(ev?.phase || ''),
                      status: ev?.status === 'error' ? 'error' : ev?.status === 'success' ? 'success' : 'progress',
                      atMs: Math.max(0, performance.now() - startedAtMs),
                    });
                  },
                },
              });
              settledAtMs[label] = Math.max(0, performance.now() - startedAtMs);
              return {
                status: 'fulfilled' as const,
                chain: String(value?.chain || ''),
                kind: String(value?.kind || ''),
              };
            } catch (error: unknown) {
              settledAtMs[label] = Math.max(0, performance.now() - startedAtMs);
              return {
                status: 'rejected' as const,
                error: String(
                  (error && typeof error === 'object' && 'message' in error)
                    ? (error as { message?: unknown }).message
                    : error || '',
                ),
              };
            }
          };

          const firstPromise = runSign('first', tempoRequest);
          await new Promise((resolve) => setTimeout(resolve, 20));
          const secondPromise = runSign('second', evmRequest);
          const [first, second] = await Promise.all([firstPromise, secondPromise]);

          const secondUserConfirmationAtMs = progressEvents.find(
            (event) => event.label === 'second' && event.phase === 'user-confirmation',
          )?.atMs;
          const firstSettledAtMs = settledAtMs.first;

          const secondConfirmedBeforeFirstSettled =
            typeof secondUserConfirmationAtMs === 'number'
            && typeof firstSettledAtMs === 'number'
            && secondUserConfirmationAtMs < firstSettledAtMs;

          return {
            ok:
              first.status === 'fulfilled'
              && second.status === 'fulfilled'
              && secondConfirmedBeforeFirstSettled,
            first,
            second,
            secondUserConfirmationAtMs,
            firstSettledAtMs,
            secondConfirmedBeforeFirstSettled,
            progressEvents,
          };
        } catch (error: unknown) {
          return {
            ok: false,
            error: String(
              (error && typeof error === 'object' && 'message' in error)
                ? (error as { message?: unknown }).message
                : error || 'enforce deployment concurrency flow failed',
            ),
          };
        }
      }, { relayerUrl: harness.baseUrl });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.first).toEqual(
        expect.objectContaining({
          status: 'fulfilled',
          chain: 'tempo',
        }),
      );
      expect(result.second).toEqual(
        expect.objectContaining({
          status: 'fulfilled',
          chain: 'evm',
        }),
      );
      expect(result.secondConfirmedBeforeFirstSettled).toBe(true);
      expect(typeof result.secondUserConfirmationAtMs).toBe('number');
      expect(typeof result.firstSettledAtMs).toBe('number');
    } finally {
      await harness.close();
    }
  });
});

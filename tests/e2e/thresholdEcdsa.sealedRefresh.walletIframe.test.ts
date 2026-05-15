import { expect, test, type Page } from '@playwright/test';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import {
  readWalletIframeThresholdPersistence,
  readWebAuthnGetCallCount,
  runPasskeySigningSessionLifecyclePhase,
  setupThresholdEcdsaSealedRefreshHarness,
  TEST_KEY_VERSION,
  TEST_SHAMIR_PRIME_B64U,
} from '../helpers/thresholdEcdsaSealedRefreshHarness';

test.describe('threshold-ecdsa sealed refresh (wallet iframe)', () => {
  test.setTimeout(180_000);

  test('registration and login can bootstrap sign then export the same one-key ECDSA session', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const flowPromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { SeamsPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `ecdsa-export-${Date.now()}.w3a-v1.testnet`;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const registration = await seams.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                stage: 'registration',
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await seams.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                stage: 'login',
                error: String(login?.error || 'unlock failed'),
              };
            }

            const bootstrap = await seams.tempo.bootstrapEcdsaSession({
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
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                stage: 'bootstrap',
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }

            const signed = await seams.tempo.signTempo({
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
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
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
                error: 'tempo sign failed',
              };
            }

            await seams.keys.exportKeypairWithUI(accountId, {
              chain: 'evm',
              variant: 'modal',
            });

            const session = await seams.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
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
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );

      const flow = await autoConfirmWalletIframeUntil(page, flowPromise, {
        timeoutMs: 180_000,
        intervalMs: 250,
      });

      expect(flow.ok, flow.error || JSON.stringify(flow)).toBe(true);
      expect(flow.sessionStatus).toBe('active');
    } finally {
      await harness.close();
    }
  });

  test('fails closed on startup when sealed refresh keyVersion parity mismatches', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl, shamirPrimeB64u }) => {
          const mod = await import('/sdk/esm/core/SeamsPasskey/index.js');
          const { SeamsPasskey } = mod as any;
          const accountId = `parity-mismatch-${Date.now()}.testnet`;
          const seams = new SeamsPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
              smartAccountDeploymentMode: 'observe',
            },
            registration: {
              mode: 'managed',
              environmentId: String(
                (globalThis as any).__w3aManagedRegistration?.environmentId || '',
              ),
              publishableKey: String(
                (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
              ),
            },
            signingSessionPersistenceMode: 'sealed_refresh_v1',
            signingSessionSeal: {
              keyVersion: 'kek-client-mismatch',
              shamirPrimeB64u,
            },
            iframeWallet: {
              walletOrigin: 'https://wallet.example.localhost',
              servicePath: '/wallet-service',
              sdkBasePath: '/sdk',
              rpIdOverride: 'example.localhost',
            },
          });

          try {
            const loginResult = await seams.auth.unlock(accountId, {
              session: { kind: 'jwt', relayUrl: relayerUrl },
            });
            if (!loginResult?.success) {
              return {
                ok: false,
                code: '',
                message: String(loginResult?.error || 'login failed'),
              };
            }
            return { ok: true };
          } catch (error: unknown) {
            return {
              ok: false,
              code: String((error as { code?: unknown })?.code || ''),
              message: String((error as Error)?.message || error),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );

      expect(result.ok).toBe(false);
      expect(result.message).toContain('keyVersion');
    } finally {
      await harness.close();
    }
  });

  test('same-tab refresh reuses sealed ECDSA signing session without extra TouchID prompt', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const loginPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefresh${Date.now()}.w3a-v1.testnet`;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const registration = await seams.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await seams.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const session = await seams.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const loginPhase = await autoConfirmWalletIframeUntil(page, loginPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(loginPhase.ok, loginPhase.error || JSON.stringify(loginPhase)).toBe(true);
      expect(loginPhase.sessionStatus).toBe('active');
      const getCallsAfterLogin = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterLogin).toBeGreaterThan(0);

      const firstSignPromise = page.evaluate(
        async ({
          relayerUrl,
          accountId,
          keyVersion,
          shamirPrimeB64u,
        }: {
          relayerUrl: string;
          accountId?: string;
          keyVersion: string;
          shamirPrimeB64u: string;
        }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);
            const bootstrap = await seams.tempo.bootstrapEcdsaSession({
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
              remainingUses: 3,
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }
            const firstSign = await seams.tempo.signTempo({
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
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x01' }],
                  accessList: [],
                  nonceKey: 0n,
                  nonce: 1n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' as const },
                  aaAuthorizationList: [],
                },
              },
              options: { confirmationConfig },
            });
            return {
              ok: firstSign?.chain === 'tempo' && firstSign?.kind === 'tempoTransaction',
              chain: String(firstSign?.chain || ''),
              kind: String(firstSign?.kind || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: loginPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstSign = await autoConfirmWalletIframeUntil(page, firstSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(firstSign.ok, JSON.stringify({ firstSign })).toBe(true);
      const getCallsAfterLoginAndFirstSign = await readWebAuthnGetCallCount(page);
      const persistenceBeforeReload = await readWalletIframeThresholdPersistence(page);
      await page.waitForTimeout(400);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const secondPhasePromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const session = await seams.auth.getWalletSession(accountId);

            const refreshedSign = await seams.tempo.signTempo({
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
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x02' }],
                  accessList: [],
                  nonceKey: 0n,
                  nonce: 2n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' as const },
                  aaAuthorizationList: [],
                },
              },
              options: { confirmationConfig },
            });

            return {
              ok: refreshedSign?.chain === 'tempo' && refreshedSign?.kind === 'tempoTransaction',
              chain: String(refreshedSign?.chain || ''),
              kind: String(refreshedSign?.kind || ''),
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'second phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: loginPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      });
      const persistenceAfterReload = await readWalletIframeThresholdPersistence(page);

      expect(secondPhase.ok, JSON.stringify({ secondPhase })).toBe(true);
      expect(
        secondPhase.sessionStatus,
        JSON.stringify({ secondPhase, persistenceBeforeReload, persistenceAfterReload }),
      ).toBe('active');
      expect(
        harness.signingSessionSealRouteCounts.removeServerSealCalls,
        JSON.stringify({ secondPhase, persistenceBeforeReload, persistenceAfterReload }),
      ).toBeGreaterThan(0);
      await page.waitForTimeout(300);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls,
        JSON.stringify({
          getCallsAfterLoginAndFirstSign,
          finalGetCalls,
          secondPhase,
          persistenceBeforeReload,
          persistenceAfterReload,
        }),
      ).toBe(getCallsAfterLoginAndFirstSign);
    } finally {
      await harness.close();
    }
  });

  test('passkey reload prompts WebAuthn after restored session exhaustion', async ({ page }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { SeamsPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefreshexhaust${Date.now()}.w3a-v1.testnet`;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 1,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const registration = await seams.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await seams.unlock(accountId, {
              signingSession: { ttlMs: 120_000, remainingUses: 1 },
            });
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const session = await seams.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.sessionStatus).toBe('active');
      const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterFirstPhase).toBeGreaterThan(0);
      await page.waitForTimeout(400);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const restoredSignPromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { SeamsPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 2,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const sign = await seams.near.executeAction({
              nearAccount: { accountId },
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-restored-exhaustion-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            return {
              ok: !!sign?.success,
              error: String(sign?.error || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'restored sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId as string,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const restoredSign = await autoConfirmWalletIframeUntil(page, restoredSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(restoredSign.ok, JSON.stringify({ restoredSign })).toBe(true);
      expect(harness.signingSessionSealRouteCounts.removeServerSealCalls).toBeGreaterThan(0);
      const getCallsAfterRestoredSign = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterRestoredSign).toBe(getCallsAfterFirstPhase);

      const reauthSignPromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { SeamsPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 2,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const sign = await seams.near.executeAction({
              nearAccount: { accountId },
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-reauth-exhaustion-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            const session = await seams.auth.getWalletSession(accountId);
            return {
              ok: !!sign?.success,
              error: String(sign?.error || ''),
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'reauth sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const reauthSign = await autoConfirmWalletIframeUntil(page, reauthSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(reauthSign.ok, JSON.stringify({ reauthSign })).toBe(true);
      // Reauth succeeds and the server budget response is authoritative. With
      // one requested use, a successful sign can immediately report exhausted.
      expect(['active', 'exhausted']).toContain(reauthSign.sessionStatus);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls,
        JSON.stringify({ getCallsAfterFirstPhase, getCallsAfterRestoredSign, finalGetCalls }),
      ).toBeGreaterThan(getCallsAfterRestoredSign);
    } finally {
      await harness.close();
    }
  });

  test('passkey lifecycle restores each signing curve after reload and prompts after exhaustion', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      for (const curve of ['ed25519', 'ecdsa'] as const) {
        const accountId = `passkeylifecycle-${curve}-${Date.now()}.w3a-v1.testnet`.toLowerCase();
        const remainingUses = 3;

        const firstPhase = await runPasskeySigningSessionLifecyclePhase(page, harness, {
          accountId,
          curve,
          phase: 'register_unlock_sign',
          tag: `${curve}-before-refresh`,
          remainingUses,
        });
        expect(firstPhase.ok, JSON.stringify(firstPhase)).toBe(true);
        expect(firstPhase.sessionStatus).toBe('active');
        const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);
        expect(getCallsAfterFirstPhase).toBeGreaterThan(0);
        await page.waitForTimeout(400);
        expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

        await page.reload();
        await page.waitForTimeout(300);

        const getCallsBeforeRestoredSign = await readWebAuthnGetCallCount(page);
        const restoredSign = await runPasskeySigningSessionLifecyclePhase(page, harness, {
          accountId,
          curve,
          phase: 'sign',
          tag: `${curve}-after-refresh-1`,
          remainingUses,
        });
        expect(restoredSign.ok, restoredSign.error || JSON.stringify(restoredSign)).toBe(true);
        expect(restoredSign.sessionStatus).toBe('active');
        const getCallsAfterRestoredSign = await readWebAuthnGetCallCount(page);
        expect(getCallsAfterRestoredSign, JSON.stringify({ curve, firstPhase, restoredSign })).toBe(
          getCallsBeforeRestoredSign,
        );

        const finalRestoredUse = await runPasskeySigningSessionLifecyclePhase(page, harness, {
          accountId,
          curve,
          phase: 'sign',
          tag: `${curve}-after-refresh-2`,
          remainingUses,
        });
        expect(
          finalRestoredUse.ok,
          finalRestoredUse.error || JSON.stringify(finalRestoredUse),
        ).toBe(true);
        const getCallsAfterFinalRestoredUse = await readWebAuthnGetCallCount(page);
        expect(
          getCallsAfterFinalRestoredUse,
          JSON.stringify({ curve, restoredSign, finalRestoredUse }),
        ).toBe(getCallsAfterRestoredSign);

        const reauthSign = await runPasskeySigningSessionLifecyclePhase(page, harness, {
          accountId,
          curve,
          phase: 'sign',
          tag: `${curve}-after-exhaustion`,
          remainingUses,
        });
        expect(reauthSign.ok, JSON.stringify({ finalRestoredUse, reauthSign })).toBe(true);
        const getCallsAfterReauth = await readWebAuthnGetCallCount(page);
        expect(getCallsAfterReauth, JSON.stringify({ curve, finalRestoredUse, reauthSign })).toBe(
          getCallsAfterFinalRestoredUse + 1,
        );
      }
    } finally {
      await harness.close();
    }
  });

  test('same-tab sealed refresh preserves Tempo/EVM prompt parity after ECDSA bootstrap in both orderings', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefreshmultichain${Date.now()}.w3a-v1.testnet`;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);

            const registration = await seams.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await seams.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const bootstrap = await seams.tempo.bootstrapEcdsaSession({
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
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }
            const evmBootstrap = await seams.evm.bootstrapEcdsaSession({
              kind: 'reuse_warm_ecdsa_bootstrap',
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              subjectId: accountId,
              chainTarget: {
                kind: 'evm' as const,
                namespace: 'eip155' as const,
                chainId: 11155111,
                networkSlug: 'evm-11155111',
              },
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 10,
            });
            if (!evmBootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                error: 'threshold ECDSA EVM bootstrap did not return ecdsaThresholdKeyId',
              };
            }

            const warmTempo = await seams.tempo.signTempo({
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
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                  accessList: [],
                  nonceKey: 0n,
                  nonce: 1n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' as const },
                  aaAuthorizationList: [],
                },
              },
              options: { confirmationConfig },
            });
            if (!warmTempo || warmTempo.kind !== 'tempoTransaction') {
              return {
                ok: false,
                error: 'tempo warm sign failed',
              };
            }

            const session = await seams.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.sessionStatus).toBe('active');
      const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterFirstPhase).toBeGreaterThan(0);
      await page.waitForTimeout(300);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      const runOrderingAfterRefresh = async (order: Array<'tempo' | 'evm'>) => {
        await page.reload();
        await page.waitForTimeout(300);

        const phasePromise = page.evaluate(
          async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u, order }) => {
            try {
              const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
              const { SeamsPasskey } = sdkMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const seams = new SeamsPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                registration: {
                  mode: 'managed',
                  environmentId: String(
                    (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                  ),
                  publishableKey: String(
                    (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                  ),
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
                iframeWallet: {
                  walletOrigin: 'https://wallet.example.localhost',
                  servicePath: '/wallet-service',
                  sdkBasePath: '/sdk',
                  rpIdOverride: 'example.localhost',
                },
              });
              seams.setConfirmationConfig(confirmationConfig as any);

              const tempoRequest = {
                chain: 'tempo' as const,
                kind: 'tempoTransaction' as const,
                senderSignatureAlgorithm: 'secp256k1' as const,
                tx: {
                  chainId: 42431,
                  maxPriorityFeePerGas: 1n,
                  maxFeePerGas: 2n,
                  gasLimit: 21_000n,
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                  accessList: [],
                  nonceKey: 0n,
                  nonce: 2n,
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
                  chainId: 11155111,
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
              const requestByChain = {
                tempo: tempoRequest,
                evm: evmRequest,
              } as const;

              const orderedResults: Array<{
                requestedChain: 'tempo' | 'evm';
                resultChain: string;
                kind: string;
              }> = [];
              for (const requestedChain of order) {
                const signed = await seams.tempo.signTempo({
                  walletSession: {
                    walletId: accountId,
                    walletSessionUserId: accountId,
                  },
                  subjectId: accountId,
                  chainTarget:
                    requestedChain === 'tempo'
                      ? {
                          kind: 'tempo' as const,
                          chainId: 42431,
                          networkSlug: 'tempo-testnet',
                        }
                      : {
                          kind: 'evm' as const,
                          namespace: 'eip155' as const,
                          chainId: 11155111,
                          networkSlug: 'ethereum-sepolia',
                        },
                  request: requestByChain[requestedChain],
                  options: { confirmationConfig },
                });
                orderedResults.push({
                  requestedChain,
                  resultChain: String(signed?.chain || ''),
                  kind: String(signed?.kind || ''),
                });
              }
              const session = await seams.auth.getWalletSession(accountId);

              return {
                ok: true,
                sessionStatus: String(session?.signingSession?.status || ''),
                orderedResults,
              };
            } catch (error: unknown) {
              return {
                ok: false,
                error: String(
                  error && typeof error === 'object' && 'message' in error
                    ? (error as { message?: unknown }).message
                    : error || 'second phase failed',
                ),
              };
            }
          },
          {
            relayerUrl: harness.relayerUrl,
            accountId: firstPhase.accountId,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            order,
          },
        );
        return await autoConfirmWalletIframeUntil(page, phasePromise, {
          timeoutMs: 120_000,
          intervalMs: 250,
        });
      };

      const tempoThenEvmPhase = await runOrderingAfterRefresh(['tempo', 'evm']);
      expect(
        tempoThenEvmPhase.ok,
        tempoThenEvmPhase.error || JSON.stringify(tempoThenEvmPhase),
      ).toBe(true);
      expect(tempoThenEvmPhase.sessionStatus).toBe('active');
      expect(tempoThenEvmPhase.orderedResults).toEqual([
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
      ]);

      const evmThenTempoPhase = await runOrderingAfterRefresh(['evm', 'tempo']);
      expect(
        evmThenTempoPhase.ok,
        evmThenTempoPhase.error || JSON.stringify(evmThenTempoPhase),
      ).toBe(true);
      expect(evmThenTempoPhase.sessionStatus).toBe('active');
      expect(evmThenTempoPhase.orderedResults).toEqual([
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
      ]);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls - getCallsAfterFirstPhase,
        JSON.stringify({
          getCallsAfterFirstPhase,
          finalGetCalls,
          firstPhase,
          tempoThenEvmPhase,
          evmThenTempoPhase,
        }),
      ).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('tab close requires TouchID re-auth even with sealed refresh enabled', async ({
    context,
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    let secondPage: Page | null = null;
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `tabclose${Date.now()}.w3a-v1.testnet`;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            seams.setConfirmationConfig(confirmationConfig as any);
            const registration = await seams.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }
            const login = await seams.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }
            return { ok: true, accountId };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      const getCallsBeforeTabClose = await readWebAuthnGetCallCount(page);
      expect(getCallsBeforeTabClose).toBeGreaterThan(0);

      await page.close();
      secondPage = await context.newPage();
      await harness.attachPage(secondPage);

      const secondPhasePromise = secondPage.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
            const { SeamsPasskey } = sdkMod as any;
            const seams = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const login = await seams.unlock(accountId);
            return {
              ok: !!login?.success,
              error: String(login?.error || ''),
              signingStatus: String(login?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'second phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const secondPhase = (await autoConfirmWalletIframeUntil(secondPage, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      })) as any;

      expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
      expect(secondPhase.signingStatus).toBe('active');
      await secondPage.waitForTimeout(300);
      const getCallsAfterTabClose = await readWebAuthnGetCallCount(secondPage);
      expect(getCallsAfterTabClose).toBeGreaterThan(getCallsBeforeTabClose);
    } finally {
      if (secondPage) {
        await secondPage.close().catch(() => undefined);
      }
      await harness.close();
    }
  });
});

type ThresholdRefreshCurve = 'ed25519' | 'ecdsa';
type ThresholdRefreshSessionKind = 'jwt' | 'cookie';

const THRESHOLD_REFRESH_MATRIX: ReadonlyArray<{
  curve: ThresholdRefreshCurve;
  sessionKind: ThresholdRefreshSessionKind;
}> = [
  { curve: 'ed25519', sessionKind: 'jwt' },
  { curve: 'ed25519', sessionKind: 'cookie' },
  { curve: 'ecdsa', sessionKind: 'jwt' },
  { curve: 'ecdsa', sessionKind: 'cookie' },
];

for (const matrixCase of THRESHOLD_REFRESH_MATRIX) {
  test.describe('threshold refresh matrix (wallet iframe)', () => {
    test.setTimeout(240_000);

    test(`rehydrates ${matrixCase.curve} with sessionKind=${matrixCase.sessionKind} after refresh`, async ({
      page,
    }) => {
      const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
      try {
        const firstPhasePromise = page.evaluate(
          async ({ relayerUrl, keyVersion, shamirPrimeB64u, curve, sessionKind }) => {
            try {
              const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
              const { SeamsPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;
              const { IndexedDBManager } = indexedDbMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const managedRuntimeScopeBootstrap = {
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              };
              const accountId =
                `refreshmatrix-${curve}-${sessionKind}-${Date.now()}.w3a-v1.testnet`.toLowerCase();
              const seams = new SeamsPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                registration: {
                  mode: 'managed',
                  environmentId: String(
                    (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                  ),
                  publishableKey: String(
                    (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                  ),
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              seams.setConfirmationConfig(confirmationConfig as any);

              const registration = await seams.registration.registerPasskeyInternal(
                accountId,
                {},
                confirmationConfig as any,
              );
              if (!registration?.success) {
                return {
                  ok: false,
                  error: String(registration?.error || 'registration failed'),
                };
              }

              const login = await seams.unlock(accountId);
              if (!login?.success) {
                return {
                  ok: false,
                  error: String(login?.error || 'unlock failed'),
                };
              }

              const signingEngine = seams.getContext().signingEngine as any;
              const accountAddress = String(accountId || '')
                .trim()
                .toLowerCase();
              const nearCandidates = ['near:testnet', 'near:mainnet'];
              let accountContext: { profileId: string; accountRef: { chainIdKey: string } } | null =
                null;
              for (const chainIdKey of nearCandidates) {
                accountContext = await IndexedDBManager.clientDB
                  .resolveProfileAccountContext({
                    chainIdKey,
                    accountAddress,
                  })
                  .catch(() => null);
                if (accountContext?.profileId) break;
              }
              if (!accountContext?.profileId || !accountContext?.accountRef?.chainIdKey) {
                return {
                  ok: false,
                  error: 'Missing generic profile/account mapping after login',
                };
              }

              const [profile, lastProfileState] = await Promise.all([
                IndexedDBManager.clientDB.getProfile(accountContext.profileId).catch(() => null),
                IndexedDBManager.clientDB.getLastProfileState().catch(() => null),
              ]);
              const preferredSignerSlot =
                lastProfileState?.profileId === accountContext.profileId
                  ? Number(lastProfileState.signerSlot)
                  : Number(profile?.defaultSignerSlot);
              const signerSlot =
                Number.isFinite(preferredSignerSlot) && preferredSignerSlot >= 1
                  ? Math.max(1, Math.floor(preferredSignerSlot))
                  : 1;
              const thresholdKeyMaterial =
                await IndexedDBManager.accountKeyMaterialDB.getKeyMaterial(
                  accountContext.profileId,
                  signerSlot,
                  accountContext.accountRef.chainIdKey,
                  'threshold_share_v1',
                );
              const thresholdPayload = (thresholdKeyMaterial?.payload || {}) as any;
              const relayerKeyId = String(thresholdPayload?.relayerKeyId || '').trim();
              const participantIds = Array.isArray(thresholdPayload?.participants)
                ? thresholdPayload.participants
                    .map((participant: any) => Number(participant?.id))
                    .filter((id: number) => Number.isFinite(id) && id > 0)
                    .map((id: number) => Math.floor(id))
                : [];
              if (!relayerKeyId || participantIds.length < 2) {
                return {
                  ok: false,
                  error: 'Missing threshold key material after login',
                };
              }

              const ecdsaBootstrap = await signingEngine.bootstrapEcdsaSession({
                nearAccountId: accountId,
                chain: 'tempo',
                source: 'manual-bootstrap',
                relayerUrl,
                participantIds,
                sessionKind: curve === 'ecdsa' ? sessionKind : 'jwt',
                ttlMs: 120_000,
                remainingUses: 8,
              });
              const thresholdSessionId = String(
                ecdsaBootstrap?.thresholdEcdsaKeyRef?.thresholdSessionId ||
                  ecdsaBootstrap?.session?.sessionId ||
                  '',
              ).trim();
              if (!thresholdSessionId) {
                return {
                  ok: false,
                  error: 'bootstrapEcdsaSession did not return thresholdSessionId',
                };
              }

              if (curve === 'ed25519') {
                const connected = await signingEngine.connectEd25519Session({
                  nearAccountId: accountId,
                  relayerUrl,
                  relayerKeyId,
                  ...(managedRuntimeScopeBootstrap.environmentId &&
                  managedRuntimeScopeBootstrap.publishableKey
                    ? { runtimeScopeBootstrap: managedRuntimeScopeBootstrap }
                    : {}),
                  participantIds,
                  sessionKind,
                  ttlMs: 120_000,
                  remainingUses: 8,
                  sessionId: thresholdSessionId,
                });
                if (!connected?.ok) {
                  return {
                    ok: false,
                    error: String(
                      connected?.message || connected?.code || 'connectEd25519Session failed',
                    ),
                  };
                }
                if (sessionKind === 'jwt') {
                  const firstSign = await seams.near.executeAction({
                    nearAccount: { accountId },
                    receiverId: 'w3a-v1.testnet',
                    actionArgs: {
                      type: ActionType.FunctionCall,
                      methodName: 'set_greeting',
                      args: { greeting: `hello-first-${curve}-${sessionKind}-${Date.now()}` },
                      gas: '30000000000000',
                      deposit: '0',
                    },
                    options: {
                      waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                      confirmationConfig,
                    },
                  });
                  if (!firstSign?.success) {
                    return {
                      ok: false,
                      error: String(firstSign?.error || 'first near sign failed'),
                    };
                  }
                }
              } else {
                if (sessionKind === 'jwt') {
                  const firstSign = await seams.tempo.signTempo({
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
                        calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
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
                  if (!firstSign || firstSign.kind !== 'tempoTransaction') {
                    return {
                      ok: false,
                      error: 'first tempo sign failed',
                    };
                  }
                }
              }

              const session = await seams.auth.getWalletSession(accountId);
              return {
                ok: true,
                accountId,
                sessionStatus: String(session?.signingSession?.status || ''),
              };
            } catch (error: unknown) {
              return {
                ok: false,
                error: String(
                  error && typeof error === 'object' && 'message' in error
                    ? (error as { message?: unknown }).message
                    : error || 'first phase failed',
                ),
              };
            }
          },
          {
            relayerUrl: harness.relayerUrl,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            curve: matrixCase.curve,
            sessionKind: matrixCase.sessionKind,
          },
        );
        const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
          timeoutMs: 150_000,
          intervalMs: 250,
        });

        expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
        expect(firstPhase.sessionStatus).toBe('active');
        const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);

        await page.reload();
        await page.waitForTimeout(300);

        const secondPhasePromise = page.evaluate(
          async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u, curve, sessionKind }) => {
            try {
              const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const { SeamsPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const seams = new SeamsPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                registration: {
                  mode: 'managed',
                  environmentId: String(
                    (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                  ),
                  publishableKey: String(
                    (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                  ),
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              seams.setConfirmationConfig(confirmationConfig as any);

              if (curve === 'ed25519') {
                if (sessionKind === 'jwt') {
                  const refreshedSign = await seams.near.executeAction({
                    nearAccount: { accountId },
                    receiverId: 'w3a-v1.testnet',
                    actionArgs: {
                      type: ActionType.FunctionCall,
                      methodName: 'set_greeting',
                      args: { greeting: `hello-refresh-${curve}-${Date.now()}` },
                      gas: '30000000000000',
                      deposit: '0',
                    },
                    options: {
                      waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                      confirmationConfig,
                    },
                  });
                  if (!refreshedSign?.success) {
                    return {
                      ok: false,
                      error: String(refreshedSign?.error || 'near sign after refresh failed'),
                    };
                  }
                }
              } else {
                if (sessionKind === 'jwt') {
                  const refreshedSign = await seams.tempo.signTempo({
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
                        calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
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
                  if (!refreshedSign || refreshedSign.kind !== 'tempoTransaction') {
                    return {
                      ok: false,
                      error: 'tempo sign after refresh failed',
                    };
                  }
                }
              }

              const session = await seams.auth.getWalletSession(accountId);
              return {
                ok: true,
                sessionStatus: String(session?.signingSession?.status || ''),
              };
            } catch (error: unknown) {
              return {
                ok: false,
                error: String(
                  error && typeof error === 'object' && 'message' in error
                    ? (error as { message?: unknown }).message
                    : error || 'second phase failed',
                ),
              };
            }
          },
          {
            relayerUrl: harness.relayerUrl,
            accountId: firstPhase.accountId,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            curve: matrixCase.curve,
            sessionKind: matrixCase.sessionKind,
          },
        );
        const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
          timeoutMs: 120_000,
          intervalMs: 250,
        });

        expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
        expect(secondPhase.sessionStatus).toBe('active');
        const finalGetCalls = await readWebAuthnGetCallCount(page);
        expect(
          finalGetCalls,
          JSON.stringify({
            matrixCase,
            getCallsAfterFirstPhase,
            finalGetCalls,
            firstPhase,
            secondPhase,
          }),
        ).toBe(getCallsAfterFirstPhase);
      } finally {
        await harness.close();
      }
    });
  });
}

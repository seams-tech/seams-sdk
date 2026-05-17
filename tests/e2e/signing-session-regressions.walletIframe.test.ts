import { expect, test, type Page } from '@playwright/test';
import {
  runEmailOtpEcdsaTempoFlow,
  runEmailOtpReloadPhase,
  setupEmailOtpEcdsaTempoHarness,
} from '../helpers/emailOtpEcdsaTempoFlow';
import {
  readWebAuthnGetCallCount,
  runPasskeySigningSessionLifecyclePhase,
  setupThresholdEcdsaSealedRefreshHarness,
  TEST_KEY_VERSION,
  TEST_SHAMIR_PRIME_B64U,
  type SealedRefreshHarness,
} from '../helpers/thresholdEcdsaSealedRefreshHarness';
import { autoConfirmWalletIframeUntil } from '../setup/flows';

async function setupPasskeyEvmSigningSession(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
    remainingUses: number;
  },
): Promise<{
  ok: boolean;
  sessionStatus?: string;
  preSessionStatus?: string;
  error?: string;
  errorName?: string;
  errorCode?: string;
  errorKeys?: string[];
  errorJson?: string;
  sealedRecordSummaries?: Array<Record<string, unknown>>;
  runtimeDiagnostics?: Record<string, unknown>;
}> {
  const setupPromise = page.evaluate(
    async ({ relayerUrl, accountId, remainingUses, keyVersion, shamirPrimeB64u }) => {
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
            remainingUses,
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
          return { ok: false, error: String(registration?.error || 'registration failed') };
        }

        const login = await seams.unlock(accountId, {
          session: {
            kind: 'jwt',
            relayUrl: relayerUrl,
            exchange: { type: 'passkey_assertion' },
          },
          signingSession: { ttlMs: 120_000, remainingUses },
        });
        if (!login?.success) {
          return { ok: false, error: String(login?.error || 'unlock failed') };
        }

        const bootstrap = await seams.evm.bootstrapEcdsaSession({
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
          remainingUses,
        });
        if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
          return { ok: false, error: 'EVM ECDSA bootstrap did not return keyRef' };
        }

        const session = await seams.auth.getWalletSession(accountId);
        return {
          ok: true,
          sessionStatus: String(session?.signingSession?.status || ''),
        };
      } catch (error: unknown) {
        return {
          ok: false,
          error:
            error && typeof error === 'object' && 'message' in error
              ? String((error as { message?: unknown }).message || '')
              : String(error || 'passkey EVM session setup failed'),
        };
      }
    },
    {
      relayerUrl: harness.relayerUrl,
      accountId: args.accountId,
      remainingUses: args.remainingUses,
      keyVersion: TEST_KEY_VERSION,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
    },
  );
  return await autoConfirmWalletIframeUntil(page, setupPromise, {
    timeoutMs: 150_000,
    intervalMs: 250,
  });
}

async function runPasskeyEvmSign(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
    tag: string;
    remainingUses: number;
  },
): Promise<{
  ok: boolean;
  kind?: string;
  chain?: string;
  sessionStatus?: string;
  error?: string;
  preSessionStatus?: string;
  errorName?: string;
  errorCode?: string;
  errorKeys?: string[];
  errorJson?: string;
  sealedRecordSummaries?: Array<Record<string, unknown>>;
  runtimeDiagnostics?: Record<string, unknown>;
}> {
  const signPromise = page.evaluate(
    async ({ relayerUrl, accountId, tag, remainingUses, keyVersion, shamirPrimeB64u }) => {
      const globalKey = '__signingSessionRegressionSeams';
      let readSealedRecordSummaries = async (): Promise<Array<Record<string, unknown>>> => [];
      let readRuntimeDiagnostics = async (): Promise<Record<string, unknown>> => ({});
      try {
        const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
        const { SeamsPasskey } = sdkMod as any;
        const confirmationConfig = {
          uiMode: 'none' as const,
          behavior: 'skipClick' as const,
          autoProceedDelay: 0,
        };
        const seams =
          (globalThis as any)[globalKey] ||
          new SeamsPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
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
              remainingUses,
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
        (globalThis as any)[globalKey] = seams;
        seams.setConfirmationConfig(confirmationConfig as any);
        readSealedRecordSummaries = async (): Promise<Array<Record<string, unknown>>> => {
          const indexedDb = globalThis.indexedDB;
          if (!indexedDb) return [];
          const openRequest = indexedDb.open('seams_wallet_v1');
          const db = await new Promise<IDBDatabase | null>((resolve) => {
            openRequest.onerror = () => resolve(null);
            openRequest.onsuccess = () => resolve(openRequest.result);
          });
          if (!db || !Array.from(db.objectStoreNames).includes('signing_session_seals_v1')) {
            db?.close();
            return [];
          }
          try {
            const tx = db.transaction('signing_session_seals_v1', 'readonly');
            const values = await new Promise<unknown[]>((resolve) => {
              const request = tx.objectStore('signing_session_seals_v1').getAll();
              request.onerror = () => resolve([]);
              request.onsuccess = () =>
                resolve(Array.isArray(request.result) ? request.result : []);
            });
            return values
              .map((value) =>
                value && typeof value === 'object' && !Array.isArray(value)
                  ? (value as Record<string, unknown>)
                  : null,
              )
              .filter((record): record is Record<string, unknown> => Boolean(record))
              .map((record) => ({
                storeKey: record.storeKey,
                walletId: record.walletId,
                userId: record.userId,
                authMethod: record.authMethod,
                curve: record.curve,
                walletSigningSessionId: record.walletSigningSessionId,
                thresholdSessionIds: record.thresholdSessionIds,
                signingRootId: record.signingRootId,
                ecdsaRestore:
                  record.ecdsaRestore &&
                  typeof record.ecdsaRestore === 'object' &&
                  !Array.isArray(record.ecdsaRestore)
                    ? {
                        chain: (record.ecdsaRestore as Record<string, unknown>).chain,
                        hasThresholdSessionAuthToken: Boolean(
                          (record.ecdsaRestore as Record<string, unknown>)
                            .thresholdSessionAuthToken,
                        ),
                        hasClientVerifyingShare: Boolean(
                          (record.ecdsaRestore as Record<string, unknown>).clientVerifyingShareB64u,
                        ),
                      }
                    : null,
                remainingUses: record.remainingUses,
                expiresAtMs: record.expiresAtMs,
              }));
          } finally {
            db.close();
          }
        };
        readRuntimeDiagnostics = async (): Promise<Record<string, unknown>> => {
          const thresholdStore =
            await import('/sdk/esm/core/signingEngine/session/persistence/records.js').catch(
              () => null,
            );
          const sealedStore =
            await import('/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js').catch(
              () => null,
            );
          const ecdsaRecords =
            thresholdStore &&
            typeof (thresholdStore as any).listStoredThresholdEcdsaSessionRecordsForWallet === 'function'
              ? (thresholdStore as any).listStoredThresholdEcdsaSessionRecordsForWallet(accountId)
              : [];
          const identities =
            sealedStore &&
            typeof (sealedStore as any).listResolvedIdentitiesForAccount === 'function'
              ? (sealedStore as any).listResolvedIdentitiesForAccount({
                  walletId: accountId,
                  curve: 'ecdsa',
                  chain: 'evm',
                })
              : [];
          return {
            ecdsaRecords: Array.isArray(ecdsaRecords)
              ? ecdsaRecords.map((record) => ({
                  source: record.source,
                  chain: record.chain,
                  thresholdSessionId: record.thresholdSessionId,
                  walletSigningSessionId: record.walletSigningSessionId,
                  signingRootId: record.signingRootId,
                  hasClientAdditiveShare: Boolean(record.clientAdditiveShare32B64u),
                  handleKind: record.clientAdditiveShareHandle?.kind,
                  remainingUses: record.remainingUses,
                }))
              : [],
            identities: Array.isArray(identities)
              ? identities.map((identity) => ({
                  authMethod: identity.authMethod,
                  curve: identity.curve,
                  chain: identity.chain,
                  thresholdSessionId: identity.thresholdSessionId,
                  walletSigningSessionId: identity.walletSigningSessionId,
                }))
              : [],
          };
        };

        const preSession = await seams.auth.getWalletSession(accountId).catch(() => null);
        const preSessionStatus = String(preSession?.signingSession?.status || '');
        const signed = await seams.tempo.signTempo({
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          subjectId: accountId,
          chainTarget: {
            kind: 'evm' as const,
            namespace: 'eip155' as const,
            chainId: 11155111,
            networkSlug: 'ethereum-sepolia',
          },
          request: {
            chain: 'evm' as const,
            kind: 'eip1559' as const,
            senderSignatureAlgorithm: 'secp256k1' as const,
            tx: {
              chainId: 11155111,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: BigInt(`1234${String(tag).length}`),
              data: `0x${Array.from(new TextEncoder().encode(tag))
                .map((byte) => byte.toString(16).padStart(2, '0'))
                .join('')}`,
              accessList: [],
            },
          },
          options: { confirmationConfig },
        });
        const session = await seams.auth.getWalletSession(accountId);
        return {
          ok: signed?.kind === 'eip1559' && signed?.chain === 'evm',
          kind: String(signed?.kind || ''),
          chain: String(signed?.chain || ''),
          sessionStatus: String(session?.signingSession?.status || ''),
          preSessionStatus,
          sealedRecordSummaries: await readSealedRecordSummaries(),
          runtimeDiagnostics: await readRuntimeDiagnostics(),
        };
      } catch (error: unknown) {
        const preSession = await (async () => {
          try {
            return await (globalThis as any)[globalKey]?.auth?.getWalletSession?.(accountId);
          } catch {
            return null;
          }
        })();
        return {
          ok: false,
          preSessionStatus: String(preSession?.signingSession?.status || ''),
          errorName:
            error && typeof error === 'object' && 'name' in error
              ? String((error as { name?: unknown }).name || '')
              : '',
          errorCode:
            error && typeof error === 'object' && 'code' in error
              ? String((error as { code?: unknown }).code || '')
              : '',
          errorKeys: error && typeof error === 'object' ? Object.keys(error as object) : [],
          errorJson:
            error && typeof error === 'object'
              ? JSON.stringify(error, Object.getOwnPropertyNames(error))
              : '',
          sealedRecordSummaries: await readSealedRecordSummaries(),
          runtimeDiagnostics: await readRuntimeDiagnostics(),
          error:
            error && typeof error === 'object' && 'message' in error
              ? String((error as { message?: unknown }).message || '')
              : String(error || 'passkey EVM sign failed'),
        };
      }
    },
    {
      relayerUrl: harness.relayerUrl,
      accountId: args.accountId,
      tag: args.tag,
      remainingUses: args.remainingUses,
      keyVersion: TEST_KEY_VERSION,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
    },
  );
  return await autoConfirmWalletIframeUntil(page, signPromise, {
    timeoutMs: 150_000,
    intervalMs: 250,
  });
}

test.describe('signing session regressions (wallet iframe)', () => {
  test.setTimeout(240_000);

  test('OTP refresh first ECDSA sign succeeds without another OTP', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `otp-ref-ecdsa-${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'otp-refresh-ecdsa-regression',
      });
      const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        skipFirstSign: true,
        signTwice: false,
      });
      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.emailOtpLogin?.warmState).toBe('ready');

      await page.reload();
      await page.waitForTimeout(300);

      const reloadPhase = await runEmailOtpReloadPhase(page, {
        harness,
        accountId,
        appSessionJwt,
        signKinds: ['tempo'],
      });

      expect(reloadPhase.ok, reloadPhase.error || JSON.stringify(reloadPhase)).toBe(true);
      expect(reloadPhase.results?.[0]).toMatchObject({
        kind: 'tempo',
        ok: true,
        chain: 'tempo',
        promptCountBefore: 0,
        promptCountAfter: 0,
        webauthnGetCountBefore: 0,
        webauthnGetCountAfter: 0,
      });
      expect(reloadPhase.emailOtpPromptCount).toBe(0);
      expect(reloadPhase.webauthnGetCount).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('OTP refresh Ed25519 export uses OTP and never passkey', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `otp-ref-ed-export-${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'otp-refresh-ed25519-export-regression',
      });
      const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
        signNearAfterLogin: true,
      });
      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.nearSign?.ok, firstPhase.nearSign?.error || '').toBe(true);

      await page.reload();
      await page.waitForTimeout(300);

      const reloadPhase = await runEmailOtpReloadPhase(page, {
        harness,
        accountId,
        appSessionJwt,
        signKinds: ['exportNear'],
      });

      expect(reloadPhase.ok, reloadPhase.error || JSON.stringify(reloadPhase)).toBe(true);
      expect(reloadPhase.results?.[0]).toMatchObject({
        kind: 'exportNear',
        ok: true,
        chain: 'near',
        promptCountBefore: 0,
        promptCountAfter: 1,
        webauthnGetCountBefore: 0,
        webauthnGetCountAfter: 0,
      });
      expect(reloadPhase.emailOtpPromptCount).toBe(1);
      expect(reloadPhase.webauthnGetCount).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('passkey unlock first ECDSA sign succeeds', async ({ page }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const result = await runPasskeySigningSessionLifecyclePhase(page, harness, {
        accountId: `passkey-unlock-ecdsa-${Date.now()}.w3a-v1.testnet`,
        curve: 'ecdsa',
        phase: 'register_unlock_sign',
        tag: 'first-ecdsa',
        remainingUses: 3,
      });
      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.chain).toBe('tempo');
      expect(result.signKind).toBe('tempoTransaction');
    } finally {
      await harness.close();
    }
  });

  test('passkey refresh EVM ECDSA uses remaining use once, then reauths once without budget exhaustion', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    const accountId = `passkey-ref-evm-${Date.now()}.w3a-v1.testnet`;
    const remainingUses = 1;
    try {
      const firstPhase = await setupPasskeyEvmSigningSession(page, harness, {
        accountId,
        remainingUses,
      });
      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.sessionStatus).toBe('active');

      const getCallsAfterRefreshSession = await readWebAuthnGetCallCount(page);
      await page.reload();
      await page.waitForTimeout(300);
      const getCallsBeforeRestoredSign = await readWebAuthnGetCallCount(page);
      expect(getCallsBeforeRestoredSign).toBe(getCallsAfterRefreshSession);

      const restoredSign = await runPasskeyEvmSign(page, harness, {
        accountId,
        tag: 'restored',
        remainingUses,
      });
      expect(restoredSign.ok, JSON.stringify(restoredSign)).toBe(true);
      expect(restoredSign.kind).toBe('eip1559');
      expect(restoredSign.chain).toBe('evm');
      expect(['active', 'exhausted']).toContain(restoredSign.sessionStatus);
      const getCallsAfterRestoredSign = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterRestoredSign).toBe(getCallsBeforeRestoredSign);

      const reauthSign = await runPasskeyEvmSign(page, harness, {
        accountId,
        tag: 'reauth',
        remainingUses,
      });
      expect(reauthSign.ok, reauthSign.error || JSON.stringify({ restoredSign, reauthSign })).toBe(
        true,
      );
      expect(reauthSign.kind).toBe('eip1559');
      expect(reauthSign.chain).toBe('evm');
      expect(String(reauthSign.error || '')).not.toContain('budget is exhausted');
      const getCallsAfterReauth = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterReauth).toBe(getCallsAfterRestoredSign + 1);
    } finally {
      await harness.close();
    }
  });
});

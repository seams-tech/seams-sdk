import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import {
  createPrfSessionSealPolicyFromEcdsaAuthSessionStore,
  createPrfSessionSealRoutesOptions,
  createPrfSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/prfSessionSeal';
import { startExpressRouter } from '../relayer/helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { installRelayServerProxyShim } from '../setup/cross-origin-headers';

const TEST_KEY_VERSION = 'kek-s-2026-02';
const TEST_SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const TEST_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const TEST_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const TEST_WEBAUTHN_GET_COUNTER_KEY = '__w3a_test_webauthn_get_calls';

type SealedRefreshHarness = {
  baseUrl: string;
  relayerUrl: string;
  prfSealRouteCounts: {
    applyServerSealCalls: number;
    removeServerSealCalls: number;
  };
  attachPage: (page: Page) => Promise<void>;
  close: () => Promise<void>;
};

async function installThresholdRegistrationBootstrapMock(
  page: Page,
  input: {
    relayerBaseUrl: string;
    threshold: unknown;
    session: { signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string> };
    onNewPublicKey: (publicKey: string) => void;
    onNewAccountId?: (accountId: string) => void;
  },
): Promise<void> {
  const threshold = input.threshold as {
    getSchemeModule?: (schemeId: string) => {
      registration?: {
        keygenFromClientVerifyingShare: (request: {
          nearAccountId: string;
          rpId: string;
          clientVerifyingShareB64u: string;
        }) => Promise<Record<string, unknown>>;
      };
    } | null;
    ecdsaRegistrationKeygenFromClientVerifyingShare?: (request: {
      userId: string;
      rpId: string;
      clientVerifyingShareB64u: string;
    }) => Promise<Record<string, unknown>>;
  };

  const edRegistrationKeygen = threshold.getSchemeModule?.('threshold-ed25519-frost-2p-v1')
    ?.registration?.keygenFromClientVerifyingShare;
  if (typeof edRegistrationKeygen !== 'function') {
    throw new Error('Missing threshold-ed25519 registration keygen hook');
  }
  if (typeof threshold.ecdsaRegistrationKeygenFromClientVerifyingShare !== 'function') {
    throw new Error('Missing threshold-ecdsa registration keygen hook');
  }

  const positiveInt = (value: unknown, fallback: number): number => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  };
  const asParticipantIds = (value: unknown, fallback: number[]): number[] => {
    if (!Array.isArray(value)) return [...fallback];
    const normalized = value
      .map((id) => Number(id))
      .filter((id) => Number.isFinite(id) && id > 0)
      .map((id) => Math.floor(id));
    return normalized.length >= 2 ? normalized : [...fallback];
  };

  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }

    const corsHeaders = corsHeadersForRoute(route);
    const payload = JSON.parse(req.postData() || '{}');
    const accountId = String(payload?.new_account_id || '').trim();
    const rpId = String(payload?.rp_id || '').trim() || 'example.localhost';
    const nowMs = Date.now();

    if (accountId) input.onNewAccountId?.(accountId);

    const signThresholdSessionJwt = async (args: {
      kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
      sessionId: string;
      relayerKeyId: string;
      participantIds: number[];
      expiresAtMs: number;
    }): Promise<string> => {
      const nowSec = Math.floor(nowMs / 1000);
      const expSec = Math.floor(args.expiresAtMs / 1000);
      return await input.session.signJwt(accountId, {
        kind: args.kind,
        sessionId: args.sessionId,
        relayerKeyId: args.relayerKeyId,
        rpId,
        participantIds: args.participantIds,
        thresholdExpiresAtMs: args.expiresAtMs,
        iat: nowSec,
        exp: expSec,
      });
    };

    const thresholdEd = payload?.threshold_ed25519 || null;
    const thresholdEdClientVerifyingShareB64u = String(
      thresholdEd?.client_verifying_share_b64u || '',
    ).trim();
    let thresholdEdResponse: Record<string, unknown> | undefined;
    if (thresholdEdClientVerifyingShareB64u) {
      const keygen = (await edRegistrationKeygen({
        nearAccountId: accountId,
        rpId,
        clientVerifyingShareB64u: thresholdEdClientVerifyingShareB64u,
      })) as Record<string, unknown>;
      if (!keygen?.ok) {
        await route.fulfill({
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({ success: false, error: String(keygen?.message || 'ed keygen') }),
        });
        return;
      }
      const publicKey = String(keygen.publicKey || '').trim();
      if (publicKey) input.onNewPublicKey(publicKey);

      const policy = thresholdEd?.session_policy || {};
      const sessionId = String(policy?.sessionId || policy?.session_id || `ed-session-${nowMs}`);
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const expiresAtMs = nowMs + ttlMs;
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const relayerKeyId = String(keygen.relayerKeyId || '').trim();
      const jwt = await signThresholdSessionJwt({
        kind: 'threshold_ed25519_session_v1',
        sessionId,
        relayerKeyId,
        participantIds,
        expiresAtMs,
      });
      thresholdEdResponse = {
        publicKey,
        relayerKeyId,
        relayerVerifyingShareB64u: String(keygen.relayerVerifyingShareB64u || ''),
        clientParticipantId: Number(keygen.clientParticipantId || 1),
        relayerParticipantId: Number(keygen.relayerParticipantId || 2),
        participantIds,
        session: {
          sessionKind: 'jwt',
          sessionId,
          expiresAtMs,
          participantIds,
          remainingUses,
          jwt,
        },
      };
    }

    const thresholdEcdsa = payload?.threshold_ecdsa || null;
    const thresholdEcdsaClientVerifyingShareB64u = String(
      thresholdEcdsa?.client_verifying_share_b64u || '',
    ).trim();
    let thresholdEcdsaResponse: Record<string, unknown> | undefined;
    if (thresholdEcdsaClientVerifyingShareB64u) {
      const ecdsaRegistrationKeygenFromClientVerifyingShare =
        threshold.ecdsaRegistrationKeygenFromClientVerifyingShare;
      if (!ecdsaRegistrationKeygenFromClientVerifyingShare) {
        throw new Error('Missing ECDSA client verifying-share registration helper');
      }
      const keygen = (await ecdsaRegistrationKeygenFromClientVerifyingShare({
        userId: accountId,
        rpId,
        clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
      })) as Record<string, unknown>;
      if (!keygen?.ok) {
        await route.fulfill({
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            success: false,
            error: String(keygen?.message || 'ecdsa keygen'),
          }),
        });
        return;
      }

      const policy = thresholdEcdsa?.session_policy || {};
      const sessionId = String(policy?.sessionId || policy?.session_id || `ecdsa-session-${nowMs}`);
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const expiresAtMs = nowMs + ttlMs;
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const relayerKeyId = String(keygen.relayerKeyId || '').trim();
      const jwt = await signThresholdSessionJwt({
        kind: 'threshold_ecdsa_session_v1',
        sessionId,
        relayerKeyId,
        participantIds,
        expiresAtMs,
      });

      thresholdEcdsaResponse = {
        relayerKeyId,
        groupPublicKeyB64u: String(keygen.groupPublicKeyB64u || ''),
        ethereumAddress: String(keygen.ethereumAddress || ''),
        relayerVerifyingShareB64u: String(keygen.relayerVerifyingShareB64u || ''),
        participantIds,
        session: {
          sessionKind: 'jwt',
          sessionId,
          expiresAtMs,
          participantIds,
          remainingUses,
          jwt,
        },
      };
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        ...(thresholdEdResponse ? { thresholdEd25519: thresholdEdResponse } : {}),
        ...(thresholdEcdsaResponse ? { thresholdEcdsa: thresholdEcdsaResponse } : {}),
      }),
    });
  });
}

async function setupThresholdEcdsaSealedRefreshHarness(page: Page): Promise<SealedRefreshHarness> {
  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();
  const accountsOnChain = new Set<string>(
    [DEFAULT_TEST_CONFIG.relayerAccount].filter((value): value is string => !!value),
  );
  const prfSealRouteCounts = {
    applyServerSealCalls: 0,
    removeServerSealCalls: 0,
  };

  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
  await service.getRelayerAccount();

  const session = createInMemoryJwtSessionAdapter();
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const relayerUrl = DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost';
  const ecdsaAuthSessionStore = (threshold as unknown as { ecdsaAuthSessionStore?: unknown })
    .ecdsaAuthSessionStore;
  if (!ecdsaAuthSessionStore) {
    throw new Error('Missing threshold ECDSA auth session store for PRF seal policy');
  }

  const router = createRelayRouter(service, {
    corsOrigins: [frontendOrigin, 'https://example.localhost', 'https://wallet.example.localhost'],
    threshold,
    session,
    prfSessionSeal: createPrfSessionSealRoutesOptions({
      sessionPolicy: createPrfSessionSealPolicyFromEcdsaAuthSessionStore(
        ecdsaAuthSessionStore as any,
      ),
      cipher: createPrfSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: TEST_KEY_VERSION,
        keys: [
          {
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            serverEncryptExponentB64u: TEST_SERVER_ENCRYPT_EXPONENT_B64U,
            serverDecryptExponentB64u: TEST_SERVER_DECRYPT_EXPONENT_B64U,
          },
        ],
      }),
      capabilities: {
        mode: 'sealed_refresh_v1',
        keyVersion: TEST_KEY_VERSION,
        shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
      },
    }),
  });
  const server = await startExpressRouter(router);

  const attachPage = async (targetPage: Page): Promise<void> => {
    await setupThresholdE2ePage(targetPage);
    await installRelayServerProxyShim(targetPage, {
      relayOrigin: relayerUrl,
      relayUpstream: server.baseUrl,
      logStyle: 'silent',
    });
    await targetPage.route(`${relayerUrl}/threshold-ecdsa/prf-seal/**`, async (route) => {
      const url = route.request().url();
      if (url.endsWith('/apply-server-seal')) {
        prfSealRouteCounts.applyServerSealCalls += 1;
      } else if (url.endsWith('/remove-server-seal')) {
        prfSealRouteCounts.removeServerSealCalls += 1;
      }
      await route.fallback();
    });
    await installThresholdRegistrationBootstrapMock(targetPage, {
      relayerBaseUrl: relayerUrl,
      threshold,
      session,
      onNewPublicKey: (publicKey) => {
        keysOnChain.add(publicKey);
        nonceByPublicKey.set(publicKey, 0);
      },
      onNewAccountId: (accountId) => {
        accountsOnChain.add(accountId);
      },
    });
    await installFastNearRpcMock(targetPage, {
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
    });
  };

  await attachPage(page);

  return {
    baseUrl: server.baseUrl,
    relayerUrl,
    prfSealRouteCounts,
    attachPage,
    close: server.close,
  };
}

async function readWebAuthnGetCallCount(page: Page): Promise<number> {
  const countsByFrame = await Promise.all(
    page.frames().map(async (frame) => {
      return await frame
        .evaluate((storageKey) => {
          const parseCount = (value: unknown): number => {
            const n = Number(value);
            return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
          };

          const globalCount = parseCount((window as any).__w3aTestWebAuthnGetCalls);
          let storedCount = 0;
          try {
            storedCount = parseCount(window.localStorage?.getItem?.(storageKey));
          } catch {}

          return {
            origin: String(window.location?.origin || 'unknown'),
            count: Math.max(globalCount, storedCount),
          };
        }, TEST_WEBAUTHN_GET_COUNTER_KEY)
        .catch(() => ({ origin: 'unknown', count: 0 }));
    }),
  );

  const maxByOrigin = new Map<string, number>();
  for (const entry of countsByFrame) {
    const origin = String(entry?.origin || 'unknown');
    const count = Number.isFinite(Number(entry?.count))
      ? Math.max(0, Math.floor(Number(entry?.count)))
      : 0;
    const previous = maxByOrigin.get(origin) ?? 0;
    if (count > previous) {
      maxByOrigin.set(origin, count);
    }
  }

  let total = 0;
  for (const count of maxByOrigin.values()) {
    total += count;
  }
  return total;
}

test.describe('threshold-ecdsa sealed refresh (wallet iframe)', () => {
  test.setTimeout(180_000);

  test('fails closed on startup when sealed refresh keyVersion parity mismatches', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl, shamirPrimeB64u }) => {
          const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
          const { TatchiPasskey } = mod as any;
          const accountId = `parity-mismatch-${Date.now()}.testnet`;
          const tatchi = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
              smartAccountDeploymentMode: 'observe',
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
            const loginResult = await tatchi.auth.unlock(accountId, {
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

  test('same-tab refresh reuses sealed PRF session without extra TouchID prompt', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefresh${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
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

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const firstSign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-before-refresh-${Date.now()}` },
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
                error: String(firstSign?.error || 'first sign failed'),
              };
            }

            const session = await tatchi.auth.getWalletSession(accountId);
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
      const getCallsAfterLoginAndFirstSign = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterLoginAndFirstSign).toBeGreaterThan(0);
      await page.waitForTimeout(400);
      expect(harness.prfSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const secondPhasePromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const session = await tatchi.auth.getWalletSession(accountId);

            const refreshedSign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-after-refresh-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });

            return {
              ok: !!refreshedSign?.success,
              error: String(refreshedSign?.error || ''),
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
        },
      );
      const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      });

      expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
      expect(secondPhase.sessionStatus).toBe('active');
      expect(harness.prfSealRouteCounts.removeServerSealCalls).toBeGreaterThan(0);

      await page.waitForTimeout(300);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls,
        JSON.stringify({
          getCallsAfterLoginAndFirstSign,
          finalGetCalls,
          firstPhase,
          secondPhase,
        }),
      ).toBe(getCallsAfterLoginAndFirstSign);
    } finally {
      await harness.close();
    }
  });

  test('same-tab sealed refresh preserves Tempo/EVM prompt parity in both orderings', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefreshmultichain${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
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

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const warmTempo = await tatchi.tempo.signTempo({
              nearAccountId: accountId,
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

            const session = await tatchi.auth.getWalletSession(accountId);
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
      expect(harness.prfSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const secondPhasePromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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
            tatchi.setConfirmationConfig(confirmationConfig as any);

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

            const runOrder = async (order: Array<'tempo' | 'evm'>) => {
              const out: Array<{
                requestedChain: 'tempo' | 'evm';
                resultChain: string;
                kind: string;
              }> = [];
              for (const requestedChain of order) {
                const signed = await tatchi.tempo.signTempo({
                  nearAccountId: accountId,
                  request: requestByChain[requestedChain],
                  options: { confirmationConfig },
                });
                out.push({
                  requestedChain,
                  resultChain: String(signed?.chain || ''),
                  kind: String(signed?.kind || ''),
                });
              }
              return out;
            };

            const tempoThenEvm = await runOrder(['tempo', 'evm']);
            const evmThenTempo = await runOrder(['evm', 'tempo']);
            const session = await tatchi.auth.getWalletSession(accountId);

            return {
              ok: true,
              sessionStatus: String(session?.signingSession?.status || ''),
              tempoThenEvm,
              evmThenTempo,
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
      const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
      expect(secondPhase.sessionStatus).toBe('active');
      expect(secondPhase.tempoThenEvm).toEqual([
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
      expect(secondPhase.evmThenTempo).toEqual([
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
        finalGetCalls,
        JSON.stringify({
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
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `tabclose${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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

            tatchi.setConfirmationConfig(confirmationConfig as any);
            const registration = await tatchi.registration.registerPasskeyInternal(
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
            const login = await tatchi.unlock(accountId);
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
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
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

            const login = await tatchi.unlock(accountId);
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
      const secondPhase = await autoConfirmWalletIframeUntil(secondPage, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      });

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
              const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
              const { TatchiPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;
              const { IndexedDBManager } = indexedDbMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const accountId =
                `refreshmatrix-${curve}-${sessionKind}-${Date.now()}.w3a-v1.testnet`.toLowerCase();
              const tatchi = new TatchiPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              tatchi.setConfirmationConfig(confirmationConfig as any);

              const registration = await tatchi.registration.registerPasskeyInternal(
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

              const login = await tatchi.unlock(accountId);
              if (!login?.success) {
                return {
                  ok: false,
                  error: String(login?.error || 'unlock failed'),
                };
              }

              const signingEngine = tatchi.getContext().signingEngine as any;
              const lastUser = await IndexedDBManager.clientDB
                .getNearAccountProjection(accountId)
                .catch(() => null);
              const deviceNumber = Number.isFinite(Number(lastUser?.deviceNumber))
                ? Math.max(1, Math.floor(Number(lastUser.deviceNumber)))
                : 1;
              const thresholdKeyMaterial = await IndexedDBManager.getNearThresholdKeyMaterial(
                accountId,
                deviceNumber,
              );
              const relayerKeyId = String(thresholdKeyMaterial?.relayerKeyId || '').trim();
              const participantIds = Array.isArray(thresholdKeyMaterial?.participants)
                ? thresholdKeyMaterial.participants
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
                  const firstSign = await tatchi.near.executeAction({
                    nearAccountId: accountId,
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
                  const firstSign = await tatchi.tempo.signTempo({
                    nearAccountId: accountId,
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

              const session = await tatchi.auth.getWalletSession(accountId);
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
              const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const { TatchiPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const tatchi = new TatchiPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              tatchi.setConfirmationConfig(confirmationConfig as any);

              if (curve === 'ed25519') {
                if (sessionKind === 'jwt') {
                  const refreshedSign = await tatchi.near.executeAction({
                    nearAccountId: accountId,
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
                  const refreshedSign = await tatchi.tempo.signTempo({
                    nearAccountId: accountId,
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

              const session = await tatchi.auth.getWalletSession(accountId);
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

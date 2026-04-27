import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WorkerResponseType } from '@/core/types/signer-worker';
import { signTransactionsWithActions } from '@/core/signingEngine/api/nearSigning';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSigning/persistence';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';

class MemorySessionStorage implements Pick<
  Storage,
  'getItem' | 'setItem' | 'removeItem' | 'clear'
> {
  private readonly store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null;
  }

  setItem(key: string, value: string): void {
    this.store.set(String(key), String(value));
  }

  removeItem(key: string): void {
    this.store.delete(String(key));
  }

  clear(): void {
    this.store.clear();
  }
}

test.describe('near signing session selection', () => {
  test('prefers the canonical threshold-ed25519 session over other signer session slots', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

    let seenSessionId = '';
    let seenThresholdSessionJwt = '';

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith('/threshold-ed25519/healthz')) {
          return new Response(JSON.stringify({ ok: true, configured: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error(`unexpected fetch in test: ${url}`);
      }) as typeof fetch;

      persistWarmSessionEd25519Capability({
        nearAccountId: 'alice.testnet',
        rpId: 'example.localhost',
        relayerUrl: 'https://relay.example.test',
        relayerKeyId: 'ed25519:relayer-key-id',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        walletSigningSessionId: 'wallet-signing-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'persisted-threshold-jwt',
        xClientBaseB64u: 'cached-client-base',
        source: 'registration',
      });

      const result = await signTransactionsWithActions(
        {
          nearRpcUrl: 'https://rpc.example.test',
          resolveThresholdEd25519SessionId: () => 'ed25519-session',
          createSigningSessionId: () => 'unexpected-generated-session',
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-alice',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: 'alice.testnet',
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-alice',
                    signerSlot: 1,
                    chainIdKey: 'near:testnet',
                    keyKind: 'threshold_share_v1' as const,
                    algorithm: 'ed25519' as const,
                    publicKey: 'ed25519:threshold-public-key',
                    payload: {
                      relayerKeyId: 'ed25519:relayer-key-id',
                      keyVersion: 'threshold-ed25519-hss-v1',
                      participants: [
                        { id: 1, role: 'client' },
                        {
                          id: 2,
                          role: 'relayer',
                          relayerUrl: 'https://relay.example.test',
                          relayerKeyId: 'ed25519:relayer-key-id',
                        },
                      ],
                    },
                    timestamp: Date.now(),
                    schemaVersion: 1,
                  }),
                },
              },
              nearContextFixture: {
                initializeUser: () => undefined,
              },
              touchIdPrompt: {
                getRpId: () => 'example.localhost',
              },
              relayerUrl: 'https://relay.example.test',
              touchConfirm: {
                getWarmSessionStatus: async ({ sessionId }: { sessionId: string }) => {
                  seenSessionId = String(sessionId || '').trim();
                  return { ok: false as const, code: 'not_found', message: 'warm-session status missing' };
                },
                claimWarmSessionMaterial: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not consume',
                }),
                clearWarmSessionMaterial: async () => undefined,
                orchestrateSigningConfirmation: async () => ({
                  intentDigest: 'intent-digest-b64u',
                  transactionContext: {
                    nearPublicKeyStr: 'ed25519:threshold-public-key',
                    nextNonce: '1',
                    txBlockHeight: '1',
                    txBlockHash: 'blockhash',
                    accessKeyInfo: { nonce: 0 },
                  },
                  credential: {
                    id: 'cred-id',
                    rawId: 'cred-rawid-b64u',
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                      clientDataJSON: 'clientDataJSON-b64u',
                      authenticatorData: 'authenticatorData-b64u',
                      signature: 'signature-b64u',
                      userHandle: '',
                    },
                    clientExtensionResults: {
                      prf: { results: { first: 'AQ', second: undefined } },
                    },
                  },
                }),
              },
              requestWorkerOperation: async ({ request }: any) => {
                seenThresholdSessionJwt = String(
                  request?.payload?.threshold?.thresholdSessionJwt || '',
                ).trim();
                return {
                  type: WorkerResponseType.SignTransactionsWithActionsSuccess,
                  payload: {
                    success: true,
                    signedTransactions: [
                      { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                    ],
                    logs: [],
                  },
                };
              },
            }) as any,
          withThresholdEd25519CommitQueue: async ({ task }) => await task(),
        },
        {
          rpcCall: { nearAccountId: 'alice.testnet', nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          transactions: [
            {
              receiverId: 'alice.testnet',
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(1);
      expect(seenSessionId).toBe('ed25519-session');
      expect(seenThresholdSessionJwt).toBe('persisted-threshold-jwt');
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      sessionStorage.clear();
      if (originalSessionStorage) {
        (globalThis as { sessionStorage?: Storage }).sessionStorage = originalSessionStorage;
      } else {
        delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
      }
      globalThis.fetch = originalFetch;
    }
  });

  test('requests exhausted Email OTP challenge only after NEAR confirmation display', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith('/threshold-ed25519/healthz')) {
          return new Response(JSON.stringify({ ok: true, configured: true }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          });
        }
        throw new Error(`unexpected fetch in test: ${url}`);
      }) as typeof fetch;

      const nearAccountId = 'otp-confirmation-order.testnet';
      const staleSessionId = 'otp-confirmation-order-stale-session';
      const refreshedSessionId = 'otp-confirmation-order-refreshed-session';
      const walletSigningSessionId = 'wallet-otp-confirmation-order';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const order: string[] = [];
      let workerSessionId = '';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        runtimePolicyScope: {
          orgId: 'org-test',
          projectId: 'project-test',
          envId: 'dev',
          signingRootVersion: 'default',
        },
        sessionId: staleSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'otp-confirmation-order-stale-jwt',
        xClientBaseB64u: 'otp-confirmation-order-stale-client-base',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      const result = await signTransactionsWithActions(
        {
          nearRpcUrl: 'https://rpc.example.test',
          resolveThresholdEd25519SessionId: () => staleSessionId,
          getWarmThresholdEd25519SessionStatusForSession: async () => ({
            sessionId: staleSessionId,
            status: 'active',
            remainingUses: 0,
            expiresAtMs: Date.now() + 60_000,
          }),
          requestEmailOtpTransactionSigningChallenge: async () => {
            order.push('challenge');
            return {
              challengeId: 'otp-confirmation-order-challenge',
              emailHint: 'a***e@example.com',
            };
          },
          loginWithEmailOtpEd25519CapabilityForSigning: async ({ otpCode }) => {
            order.push(`complete:${otpCode}`);
            persistWarmSessionEd25519Capability({
              nearAccountId,
              rpId,
              relayerUrl,
              relayerKeyId,
              participantIds: [1, 2],
              runtimePolicyScope: {
                orgId: 'org-test',
                projectId: 'project-test',
                envId: 'dev',
                signingRootVersion: 'default',
              },
              sessionId: refreshedSessionId,
              walletSigningSessionId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 1,
              jwt: 'otp-confirmation-order-refreshed-jwt',
              xClientBaseB64u: 'otp-confirmation-order-refreshed-client-base',
              source: 'email_otp',
              emailOtpAuthContext: {
                policy: 'per_operation',
                retention: 'single_use',
                reason: 'sign',
                authMethod: 'email_otp',
              },
            });
            return { sessionId: refreshedSessionId };
          },
          createSigningSessionId: () => 'unexpected-generated-session',
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-otp-confirmation-order',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-otp-confirmation-order',
                    signerSlot: 1,
                    chainIdKey: 'near:testnet',
                    keyKind: 'threshold_share_v1' as const,
                    algorithm: 'ed25519' as const,
                    publicKey: 'ed25519:threshold-public-key',
                    payload: {
                      relayerKeyId,
                      keyVersion: 'threshold-ed25519-hss-v1',
                      participants: [
                        { id: 1, role: 'client' },
                        { id: 2, role: 'relayer', relayerUrl, relayerKeyId },
                      ],
                    },
                    timestamp: Date.now(),
                    schemaVersion: 1,
                  }),
                },
              },
              nearContextFixture: {
                initializeUser: () => undefined,
              },
              touchIdPrompt: {
                getRpId: () => rpId,
              },
              relayerUrl,
              touchConfirm: {
                getWarmSessionStatus: async () => ({
                  ok: false as const,
                  code: 'not_found',
                  message: 'warm-session status missing',
                }),
                claimWarmSessionMaterial: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not claim',
                }),
                clearWarmSessionMaterial: async () => undefined,
                orchestrateSigningConfirmation: async (params: any) => {
                  order.push('confirm');
                  expect(params?.emailOtpPrompt?.challengeId).toBe(
                    'otp-confirmation-order-challenge',
                  );
                  return {
                    intentDigest: 'intent-digest-b64u',
                    transactionContext: {
                      nearPublicKeyStr: 'ed25519:threshold-public-key',
                      nextNonce: '1',
                      txBlockHeight: '1',
                      txBlockHash: 'blockhash',
                      accessKeyInfo: { nonce: 0 },
                    },
                    otpCode: '246810',
                    emailOtpChallengeId: 'otp-confirmation-order-challenge',
                    credential: undefined,
                  };
                },
              },
              requestWorkerOperation: async ({ request }: any) => {
                workerSessionId = String(request?.sessionId || '').trim();
                expect(String(request?.payload?.threshold?.thresholdSessionJwt || '')).toBe(
                  'otp-confirmation-order-refreshed-jwt',
                );
                return {
                  type: WorkerResponseType.SignTransactionsWithActionsSuccess,
                  payload: {
                    success: true,
                    signedTransactions: [
                      { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                    ],
                    logs: [],
                  },
                };
              },
            }) as any,
          withThresholdEd25519CommitQueue: async ({ task }) => await task(),
        },
        {
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          onEvent: (event) => {
            if (event.phase === SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED) {
              order.push('display');
            }
          },
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(workerSessionId).toBe(refreshedSessionId);
      expect(order).toEqual(['display', 'challenge', 'confirm', 'complete:246810']);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      sessionStorage.clear();
      if (originalSessionStorage) {
        (globalThis as { sessionStorage?: Storage }).sessionStorage = originalSessionStorage;
      } else {
        delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
      }
      globalThis.fetch = originalFetch;
    }
  });
});

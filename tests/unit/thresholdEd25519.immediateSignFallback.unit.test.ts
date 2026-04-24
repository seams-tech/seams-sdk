import { expect, test } from '@playwright/test';
import { signTransactionsWithActions } from '@/core/signingEngine/orchestration/near/transactionsFlow';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSessionPersistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  markThresholdEd25519EmailOtpSessionConsumedForAccount,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { createWalletSigningBudgetLedger } from '@/core/signingEngine/session/WalletSigningBudgetLedger';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSessionTypes';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/SigningLaneBuilders';
import { ActionType } from '@/core/types/actions';
import { SigningEventPhase, type SigningFlowEvent } from '@/core/types/sdkSentEvents';
import { WorkerResponseType } from '@/core/types/signer-worker';

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

async function withNearThresholdTestEnv<T>(run: () => Promise<T>): Promise<T> {
  const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
  const originalFetch = globalThis.fetch;
  const sessionStorage = new MemorySessionStorage();
  (
    globalThis as {
      sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
    }
  ).sessionStorage = sessionStorage;

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

  clearAllStoredThresholdEd25519SessionRecords();

  try {
    return await run();
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
}

function createNearThresholdRuntimeCtx({
  nearAccountId,
  relayerUrl,
  relayerKeyId,
  rpId,
  orchestrateSigningConfirmation,
  requestWorkerOperation,
}: {
  nearAccountId: string;
  relayerUrl: string;
  relayerKeyId: string;
  rpId: string;
  orchestrateSigningConfirmation: (params: any) => Promise<any>;
  requestWorkerOperation: (params: any) => Promise<any>;
}) {
  return {
    indexedDB: {
      clientDB: {
        resolveProfileAccountContext: async () => ({
          profileId: `profile-${nearAccountId}`,
          accountRef: {
            chainIdKey: 'near:testnet',
            accountAddress: nearAccountId,
          },
        }),
      },
      accountKeyMaterialDB: {
        getKeyMaterial: async () => ({
          profileId: `profile-${nearAccountId}`,
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
              {
                id: 2,
                role: 'relayer',
                relayerUrl,
                relayerKeyId,
              },
            ],
          },
          timestamp: Date.now(),
          schemaVersion: 1,
        }),
      },
    },
    nonceManager: {
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
      orchestrateSigningConfirmation,
    },
    requestWorkerOperation,
  } as any;
}

test.describe('threshold ed25519 immediate signing fallback', () => {
  test('uses Email OTP client-base session material without falling back to WebAuthn', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

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

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const nearAccountId = 'email-otp-ed25519.testnet';
      const sessionId = 'email-otp-ed25519-session';
      const walletSigningSessionId = 'wallet-email-otp-ed25519-session';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        sessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'email-otp-threshold-jwt',
        xClientBaseB64u: 'email-otp-x-client-base',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      let resolvedSigningAuthMode = '';
      let resolvedSigningAuthPlanKind = '';
      let claimCalls = 0;
      let workerThresholdSessionJwt = '';
      let workerCredentialJson = '';
      let workerXClientBaseB64u = '';
      const progressEvents: SigningFlowEvent[] = [];

      const signed = await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile-email-otp-ed25519',
                accountRef: {
                  chainIdKey: 'near:testnet',
                  accountAddress: nearAccountId,
                },
              }),
            },
            accountKeyMaterialDB: {
              getKeyMaterial: async () => ({
                profileId: 'profile-email-otp-ed25519',
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
                    {
                      id: 2,
                      role: 'relayer',
                      relayerUrl,
                      relayerKeyId,
                    },
                  ],
                },
                timestamp: Date.now(),
                schemaVersion: 1,
              }),
            },
          },
          nonceManager: {
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
            claimWarmSessionMaterial: async () => {
              claimCalls += 1;
              return { ok: false as const, code: 'unexpected', message: 'should not claim' };
            },
            clearWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async (params: any) => {
              resolvedSigningAuthMode = String(params?.signingAuthMode || '');
              resolvedSigningAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              return {
                intentDigest: 'intent-digest-b64u',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:threshold-public-key',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: undefined,
              };
            },
          },
          requestWorkerOperation: async ({ request }: any) => {
            workerThresholdSessionJwt = String(
              request?.payload?.threshold?.thresholdSessionJwt || '',
            ).trim();
            workerCredentialJson = String(request?.payload?.credential || '').trim();
            workerXClientBaseB64u = String(
              request?.payload?.threshold?.xClientBaseB64u || '',
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
        } as any,
        transactions: [
          {
            receiverId: nearAccountId,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          },
        ],
        rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId,
        onEvent: (event) => progressEvents.push(event),
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('warmSession');
      expect(claimCalls).toBe(0);
      expect(workerThresholdSessionJwt).toBe('email-otp-threshold-jwt');
      expect(workerCredentialJson).toBe('');
      expect(workerXClientBaseB64u).toBe('email-otp-x-client-base');

      const phases = progressEvents.map((event) => event.phase);
      expect(phases).toEqual(
        expect.arrayContaining([
          SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
          SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
          SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
          SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
          SigningEventPhase.STEP_10_COMMIT_STARTED,
          SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
          SigningEventPhase.STEP_15_COMPLETED,
        ]),
      );
      expect(phases.indexOf(SigningEventPhase.STEP_05_CONFIRMATION_APPROVED)).toBeLessThan(
        phases.indexOf(SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED),
      );
      expect(phases.indexOf(SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED)).toBeLessThan(
        phases.indexOf(SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE),
      );
      expect(phases.indexOf(SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE)).toBeLessThan(
        phases.indexOf(SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED),
      );
      expect(phases.indexOf(SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED)).toBeLessThan(
        phases.indexOf(SigningEventPhase.STEP_10_COMMIT_STARTED),
      );

      const signerPrepareStarted = progressEvents.find(
        (event) => event.phase === SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
      );
      expect(signerPrepareStarted).toMatchObject({
        step: 8,
        status: 'running',
        message: 'Preparing NEAR signer',
      });
      const signerPrepareSucceeded = progressEvents.find(
        (event) => event.phase === SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
      );
      expect(signerPrepareSucceeded).toMatchObject({
        step: 8,
        status: 'succeeded',
        message: 'NEAR signer ready',
        data: expect.objectContaining({
          signer: 'threshold-ed25519',
          clientBaseSource: 'cached',
        }),
      });
      const authComplete = progressEvents.find(
        (event) => event.phase === SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
      );
      expect(authComplete).toMatchObject({
        step: 7,
        status: 'succeeded',
        authMethod: 'warm_session',
      });
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

  test('uses Email OTP prompt and refreshed client-base session for per-operation signing', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

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

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const nearAccountId = 'email-otp-ed25519-per-operation.testnet';
      const staleSessionId = 'email-otp-ed25519-consumed-session';
      const refreshedSessionId = 'email-otp-ed25519-refreshed-session';
      const walletSigningSessionId = 'wallet-email-otp-ed25519-per-operation';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        jwt: 'email-otp-stale-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
          consumedAtMs: Date.now() - 1_000,
        },
      });

      let resolvedSigningAuthMode = '';
      let resolvedSigningAuthPlanKind = '';
      let capturedChallengeId = '';
      let completedOtpCode = '';
      let workerThresholdSessionJwt = '';
      let workerXClientBaseB64u = '';
      let workerCredentialJson = '';
      let consumedUses = 0;
      const emailOtpSideEffectOrder: string[] = [];

      const signed = await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile-email-otp-ed25519-per-operation',
                accountRef: {
                  chainIdKey: 'near:testnet',
                  accountAddress: nearAccountId,
                },
              }),
            },
            accountKeyMaterialDB: {
              getKeyMaterial: async () => ({
                profileId: 'profile-email-otp-ed25519-per-operation',
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
                    {
                      id: 2,
                      role: 'relayer',
                      relayerUrl,
                      relayerKeyId,
                    },
                  ],
                },
                timestamp: Date.now(),
                schemaVersion: 1,
              }),
            },
          },
          nonceManager: {
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
              emailOtpSideEffectOrder.push('confirm');
              resolvedSigningAuthMode = String(params?.signingAuthMode || '');
              resolvedSigningAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              capturedChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
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
                credential: undefined,
              };
            },
          },
          requestWorkerOperation: async ({ request }: any) => {
            workerThresholdSessionJwt = String(
              request?.payload?.threshold?.thresholdSessionJwt || '',
            ).trim();
            workerCredentialJson = String(request?.payload?.credential || '').trim();
            workerXClientBaseB64u = String(
              request?.payload?.threshold?.xClientBaseB64u || '',
            ).trim();
            return {
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([2]) },
                ],
                logs: [],
              },
            };
          },
        } as any,
        transactions: [
          {
            receiverId: nearAccountId,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          },
          {
            receiverId: nearAccountId,
            actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
          },
        ],
        rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
        onEvent: (event) => {
          if (event.phase === SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED) {
            emailOtpSideEffectOrder.push('display');
          }
        },
        signerSlot: 1,
        sessionId: staleSessionId,
        emailOtpSigning: {
          prepare: async () => {
            emailOtpSideEffectOrder.push('prepare');
            return {
              challengeId: 'near-email-otp-challenge',
              emailHint: 'a***e@example.com',
            };
          },
          complete: async (otpCode: string) => {
            completedOtpCode = otpCode;
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
              jwt: 'email-otp-refreshed-threshold-jwt',
              xClientBaseB64u: 'email-otp-refreshed-x-client-base',
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
        },
        walletSigningBudgetLedger: createWalletSigningBudgetLedger({
          consumeUse: async ({ uses }) => {
            consumedUses = uses;
            markThresholdEd25519EmailOtpSessionConsumedForAccount({
              nearAccountId,
              thresholdSessionId: refreshedSessionId,
              uses,
            });
            return {
              sessionId: refreshedSessionId,
              status: 'exhausted',
              authMethod: 'email_otp',
              retention: 'single_use',
            };
          },
        }),
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(2);
      expect(consumedUses).toBe(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('emailOtpReauth');
      expect(capturedChallengeId).toBe('near-email-otp-challenge');
      expect(emailOtpSideEffectOrder).toEqual(['display', 'prepare', 'confirm']);
      expect(completedOtpCode).toBe('246810');
      expect(workerThresholdSessionJwt).toBe('email-otp-refreshed-threshold-jwt');
      expect(workerCredentialJson).toBe('');
      expect(workerXClientBaseB64u).toBe('email-otp-refreshed-x-client-base');
      const consumed = getStoredThresholdEd25519SessionRecordForAccount(nearAccountId);
      expect(consumed?.thresholdSessionId).toBe(refreshedSessionId);
      expect(consumed?.emailOtpAuthContext?.consumedAtMs).toBeGreaterThan(0);
      expect(String(consumed?.xClientBaseB64u || '')).toBe('');
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

  test('asks Email OTP users to verify again when Ed25519 session material is not hydrated', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

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

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const nearAccountId = 'email-otp-refresh-required.testnet';
      const sessionId = 'email-otp-refresh-required-session';
      const walletSigningSessionId = 'wallet-email-otp-refresh-required';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        sessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'email-otp-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      await expect(
        signTransactionsWithActions({
          ctx: {
            indexedDB: {
              clientDB: {
                resolveProfileAccountContext: async () => ({
                  profileId: 'profile-email-otp-refresh-required',
                  accountRef: {
                    chainIdKey: 'near:testnet',
                    accountAddress: nearAccountId,
                  },
                }),
              },
              accountKeyMaterialDB: {
                getKeyMaterial: async () => ({
                  profileId: 'profile-email-otp-refresh-required',
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
                      {
                        id: 2,
                        role: 'relayer',
                        relayerUrl,
                        relayerKeyId,
                      },
                    ],
                  },
                  timestamp: Date.now(),
                  schemaVersion: 1,
                }),
              },
            },
            nonceManager: {
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
              orchestrateSigningConfirmation: async () => {
                throw new Error('should not open confirmation');
              },
            },
            requestWorkerOperation: async () => {
              throw new Error('should not sign');
            },
          } as any,
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          sessionId,
        }),
      ).rejects.toThrow('[email-otp] verify Email OTP again before NEAR threshold signing');
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

  test('falls back to WebAuthn when the warm session cache is missing but the persisted session remains valid', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const originalFetch = globalThis.fetch;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

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

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const nearAccountId = 'immediate-fallback.testnet';
      const sessionId = 'threshold-ed25519-session-1';
      const walletSigningSessionId = 'wallet-immediate-fallback';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        sessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'persisted-threshold-jwt',
        xClientBaseB64u: 'persisted-x-client-base',
        source: 'registration',
      });

      const dummyCredential = {
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
      };

      let resolvedSigningAuthMode: string | null = null;
      let resolvedSigningAuthPlanKind: string | null = null;
      let claimCalls = 0;
      let workerThresholdSessionJwt = '';
      let workerCredentialJson = '';

      const signed = await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile-immediate-fallback',
                accountRef: {
                  chainIdKey: 'near:testnet',
                  accountAddress: nearAccountId,
                },
              }),
            },
            accountKeyMaterialDB: {
              getKeyMaterial: async () => ({
                profileId: 'profile-immediate-fallback',
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
                    {
                      id: 2,
                      role: 'relayer',
                      relayerUrl,
                      relayerKeyId,
                    },
                  ],
                },
                timestamp: Date.now(),
                schemaVersion: 1,
              }),
            },
          },
          nonceManager: {
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
            claimWarmSessionMaterial: async () => {
              claimCalls += 1;
              return { ok: false as const, code: 'unexpected', message: 'should not claim' };
            },
            clearWarmSessionMaterial: async () => undefined,
            orchestrateSigningConfirmation: async (params: any) => {
              resolvedSigningAuthMode = String(params?.signingAuthMode || '');
              resolvedSigningAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              return {
                intentDigest: 'intent-digest-b64u',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:threshold-public-key',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: dummyCredential,
              };
            },
          },
          requestWorkerOperation: async ({ request }: any) => {
            workerThresholdSessionJwt = String(
              request?.payload?.threshold?.thresholdSessionJwt || '',
            ).trim();
            workerCredentialJson = String(request?.payload?.credential || '').trim();
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
        } as any,
        transactions: [
          {
            receiverId: nearAccountId,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          },
        ],
        rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId,
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('passkeyReauth');
      expect(claimCalls).toBe(0);
      expect(workerThresholdSessionJwt).toBe('persisted-threshold-jwt');
      expect(workerCredentialJson).toContain('cred-id');
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

  test('emits confirmed NEAR passkey and threshold reconnect side-effect traces', async () => {
    await withNearThresholdTestEnv(async () => {
      const originalLocalStorage = (globalThis as { localStorage?: Storage }).localStorage;
      const originalConsoleDebug = console.debug;
      const localStorage = new MemorySessionStorage();
      (
        globalThis as {
          localStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
        }
      ).localStorage = localStorage;
      localStorage.setItem('tatchi:debug:signing-session', '1');
      const debugCalls: unknown[][] = [];
      console.debug = (...args: unknown[]) => {
        debugCalls.push(args);
      };

      try {
        const nearAccountId = 'near-passkey-trace.testnet';
        const thresholdSessionId = 'near-passkey-trace-session';
        const walletSigningSessionId = 'wallet-near-passkey-trace';
        const relayerUrl = 'https://relay.example.test';
        const relayerKeyId = 'ed25519:relayer-key-id';
        const rpId = 'example.localhost';
        const dummyCredential = {
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
        };

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
          sessionId: thresholdSessionId,
          walletSigningSessionId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          jwt: 'near-passkey-trace-threshold-jwt',
          xClientBaseB64u: 'near-passkey-trace-x-client-base',
          source: 'registration',
        });

        let reconnectCalls = 0;
        const signingLane = buildNearTransactionSigningLane({
          accountId: nearAccountId as any,
          authMethod: 'passkey',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          storageSource: 'registration',
        });

        const signed = await signTransactionsWithActions({
          ctx: createNearThresholdRuntimeCtx({
            nearAccountId,
            relayerUrl,
            relayerKeyId,
            rpId,
            orchestrateSigningConfirmation: async (params: any) => {
              params?.onProgress?.({
                requestId: 'request-near-passkey-trace',
                step: 1,
                phase: 'auth.passkey.prompt.started',
                status: 'running',
              });
              return {
                intentDigest: 'intent-digest-b64u',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:threshold-public-key',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: dummyCredential,
              };
            },
            requestWorkerOperation: async () => ({
              type: WorkerResponseType.SignTransactionsWithActionsSuccess,
              payload: {
                success: true,
                signedTransactions: [
                  { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
                ],
                logs: [],
              },
            }),
          }),
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          sessionId: thresholdSessionId,
          signingAuthPlan: {
            kind: 'passkeyReauth',
            method: 'passkey',
          },
          signingLane,
          passkeyEd25519Reconnect: {
            reconnect: async () => {
              reconnectCalls += 1;
              return { sessionId: thresholdSessionId };
            },
          },
        });

        expect(signed).toHaveLength(1);
        expect(reconnectCalls).toBe(1);
        const boundaryEvents = debugCalls
          .filter(([label]) => label === '[SigningBoundary][near]')
          .map(([, event]) => event as any)
          .filter((event) => event?.event === 'auth_side_effect_started');
        expect(boundaryEvents.map((event) => event.sideEffect)).toEqual([
          'passkey_reauth',
          'threshold_reconnect',
        ]);
        expect(boundaryEvents.every((event) => event.phase === 'confirmed')).toBe(true);
        expect(boundaryEvents.every((event) => event.lane?.authMethod === 'passkey')).toBe(true);
        expect(boundaryEvents.every((event) => event.lane?.curve === 'ed25519')).toBe(true);
      } finally {
        console.debug = originalConsoleDebug;
        localStorage.clear();
        if (originalLocalStorage) {
          (globalThis as { localStorage?: Storage }).localStorage = originalLocalStorage;
        } else {
          delete (globalThis as { localStorage?: Storage }).localStorage;
        }
      }
    });
  });

  test('records wallet signing budget once when the same NEAR signing operation completes twice', async () => {
    await withNearThresholdTestEnv(async () => {
      const nearAccountId = 'near-budget-idempotent.testnet';
      const thresholdSessionId = 'near-budget-idempotent-session';
      const walletSigningSessionId = 'wallet-near-budget-idempotent';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const signingOperationId = SigningSessionIds.signingOperation(
        'near-flow-duplicate-success-operation',
      );

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
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'near-budget-idempotent-threshold-jwt',
        xClientBaseB64u: 'near-budget-idempotent-x-client-base',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      const consumeCalls: any[] = [];
      const walletSigningBudgetLedger = createWalletSigningBudgetLedger({
        consumeUse: async (input) => {
          consumeCalls.push(input);
          return {
            sessionId: walletSigningSessionId,
            status: 'active',
            authMethod: 'email_otp',
            retention: 'session',
            remainingUses: 9,
          };
        },
      });
      let confirmationCalls = 0;
      let workerCalls = 0;

      const signOnce = async () =>
        await signTransactionsWithActions({
          ctx: createNearThresholdRuntimeCtx({
            nearAccountId,
            relayerUrl,
            relayerKeyId,
            rpId,
            orchestrateSigningConfirmation: async () => {
              confirmationCalls += 1;
              return {
                intentDigest: 'intent-digest-b64u',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:threshold-public-key',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: undefined,
              };
            },
            requestWorkerOperation: async () => {
              workerCalls += 1;
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
          }),
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          sessionId: thresholdSessionId,
          signingOperationId,
          walletSigningBudgetLedger,
        });

      await signOnce();
      await signOnce();

      expect(confirmationCalls).toBe(2);
      expect(workerCalls).toBe(2);
      expect(consumeCalls).toHaveLength(1);
      expect(consumeCalls[0]).toMatchObject({
        nearAccountId,
        walletSigningSessionId,
        uses: 1,
        reason: 'transaction_sign',
      });
    });
  });

  test('does not record wallet signing budget when NEAR confirmation is cancelled', async () => {
    await withNearThresholdTestEnv(async () => {
      const nearAccountId = 'near-budget-cancelled.testnet';
      const thresholdSessionId = 'near-budget-cancelled-session';
      const walletSigningSessionId = 'wallet-near-budget-cancelled';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'near-budget-cancelled-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
          consumedAtMs: Date.now() - 1_000,
        },
      });

      const consumeCalls: any[] = [];
      let completedOtpCode = '';
      let workerCalls = 0;

      await expect(
        signTransactionsWithActions({
          ctx: createNearThresholdRuntimeCtx({
            nearAccountId,
            relayerUrl,
            relayerKeyId,
            rpId,
            orchestrateSigningConfirmation: async () => {
              throw new Error('User rejected signing request');
            },
            requestWorkerOperation: async () => {
              workerCalls += 1;
              throw new Error('should not sign after cancellation');
            },
          }),
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          sessionId: thresholdSessionId,
          emailOtpSigning: {
            prepare: async () => ({
              challengeId: 'near-budget-cancelled-challenge',
              emailHint: 'a***e@example.com',
            }),
            complete: async (otpCode: string) => {
              completedOtpCode = otpCode;
              return { sessionId: thresholdSessionId };
            },
          },
          walletSigningBudgetLedger: createWalletSigningBudgetLedger({
            consumeUse: async (input) => {
              consumeCalls.push(input);
              return {
                sessionId: walletSigningSessionId,
                status: 'active',
                authMethod: 'email_otp',
                retention: 'single_use',
                remainingUses: 0,
              };
            },
          }),
        }),
      ).rejects.toThrow('User rejected signing request');

      expect(workerCalls).toBe(0);
      expect(completedOtpCode).toBe('');
      expect(consumeCalls).toHaveLength(0);
    });
  });

  test('records wallet signing budget only after successful NEAR Email OTP resend signing', async () => {
    await withNearThresholdTestEnv(async () => {
      const nearAccountId = 'near-budget-otp-resend.testnet';
      const staleSessionId = 'near-budget-otp-resend-stale-session';
      const refreshedSessionId = 'near-budget-otp-resend-refreshed-session';
      const walletSigningSessionId = 'wallet-near-budget-otp-resend';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        jwt: 'near-budget-otp-resend-stale-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
          consumedAtMs: Date.now() - 1_000,
        },
      });

      const consumeCalls: any[] = [];
      let resendCalls = 0;
      let completedOtpCode = '';
      let completedChallengeId = '';

      const signed = await signTransactionsWithActions({
        ctx: createNearThresholdRuntimeCtx({
          nearAccountId,
          relayerUrl,
          relayerKeyId,
          rpId,
          orchestrateSigningConfirmation: async (params: any) => {
            expect(consumeCalls).toHaveLength(0);
            const resendResult = await params.emailOtpPrompt.onResend();
            expect(resendResult.challengeId).toBe('near-budget-otp-resend-challenge-2');
            expect(consumeCalls).toHaveLength(0);
            return {
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: 'ed25519:threshold-public-key',
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              otpCode: '135790',
              emailOtpChallengeId: resendResult.challengeId,
              credential: undefined,
            };
          },
          requestWorkerOperation: async () => ({
            type: WorkerResponseType.SignTransactionsWithActionsSuccess,
            payload: {
              success: true,
              signedTransactions: [
                { transaction: {}, signature: {}, borshBytes: new Uint8Array([1]) },
              ],
              logs: [],
            },
          }),
        }),
        transactions: [
          {
            receiverId: nearAccountId,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          },
        ],
        rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
        signerSlot: 1,
        sessionId: staleSessionId,
        emailOtpSigning: {
          prepare: async () => ({
            challengeId: 'near-budget-otp-resend-challenge-1',
            emailHint: 'a***e@example.com',
          }),
          resend: async () => {
            resendCalls += 1;
            return {
              challengeId: 'near-budget-otp-resend-challenge-2',
              emailHint: 'a***e@example.com',
            };
          },
          complete: async (otpCode: string, challengeId?: string) => {
            completedOtpCode = otpCode;
            completedChallengeId = String(challengeId || '');
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
              jwt: 'near-budget-otp-resend-refreshed-threshold-jwt',
              xClientBaseB64u: 'near-budget-otp-resend-refreshed-x-client-base',
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
        },
        walletSigningBudgetLedger: createWalletSigningBudgetLedger({
          consumeUse: async (input) => {
            consumeCalls.push(input);
            markThresholdEd25519EmailOtpSessionConsumedForAccount({
              nearAccountId,
              thresholdSessionId: refreshedSessionId,
              uses: input.uses,
            });
            return {
              sessionId: walletSigningSessionId,
              status: 'exhausted',
              authMethod: 'email_otp',
              retention: 'single_use',
              remainingUses: 0,
            };
          },
        }),
      });

      expect(signed).toHaveLength(1);
      expect(resendCalls).toBe(1);
      expect(completedOtpCode).toBe('135790');
      expect(completedChallengeId).toBe('near-budget-otp-resend-challenge-2');
      expect(consumeCalls).toHaveLength(1);
      expect(consumeCalls[0]).toMatchObject({
        nearAccountId,
        walletSigningSessionId,
        uses: 1,
        reason: 'transaction_sign',
      });
    });
  });

  test('does not record wallet signing budget when NEAR worker signing fails', async () => {
    await withNearThresholdTestEnv(async () => {
      const nearAccountId = 'near-budget-worker-failure.testnet';
      const thresholdSessionId = 'near-budget-worker-failure-session';
      const walletSigningSessionId = 'wallet-near-budget-worker-failure';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

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
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'near-budget-worker-failure-threshold-jwt',
        xClientBaseB64u: 'near-budget-worker-failure-x-client-base',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      const consumeCalls: any[] = [];
      let confirmationCalls = 0;

      await expect(
        signTransactionsWithActions({
          ctx: createNearThresholdRuntimeCtx({
            nearAccountId,
            relayerUrl,
            relayerKeyId,
            rpId,
            orchestrateSigningConfirmation: async () => {
              confirmationCalls += 1;
              return {
                intentDigest: 'intent-digest-b64u',
                transactionContext: {
                  nearPublicKeyStr: 'ed25519:threshold-public-key',
                  nextNonce: '1',
                  txBlockHeight: '1',
                  txBlockHash: 'blockhash',
                  accessKeyInfo: { nonce: 0 },
                },
                credential: undefined,
              };
            },
            requestWorkerOperation: async () => {
              throw new Error('worker signing failed');
            },
          }),
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          sessionId: thresholdSessionId,
          walletSigningBudgetLedger: createWalletSigningBudgetLedger({
            consumeUse: async (input) => {
              consumeCalls.push(input);
              return {
                sessionId: walletSigningSessionId,
                status: 'active',
                authMethod: 'email_otp',
                retention: 'session',
                remainingUses: 9,
              };
            },
          }),
        }),
      ).rejects.toThrow('worker signing failed');

      expect(confirmationCalls).toBe(1);
      expect(consumeCalls).toHaveLength(0);
    });
  });
});

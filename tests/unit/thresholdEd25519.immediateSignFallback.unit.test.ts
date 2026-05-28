import { expect, test } from '@playwright/test';
import { runNearTransactionsWithActionsSigning as signPreparedTransactionsWithActions } from '@/core/signingEngine/flows/signNear/signTransactions';
import { connectEd25519Session } from '@/core/signingEngine/threshold/ed25519/connectSession';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  markThresholdEd25519EmailOtpSessionConsumedForAccount,
} from '@/core/signingEngine/session/persistence/records';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import {
  SigningKeyRefIntentKind,
  SigningSessionIds,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/operationState/types';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
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
      keyMaterialStore: {
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
      clearVolatileWarmSessionMaterial: async () => undefined,
      orchestrateSigningConfirmation,
    },
    requestWorkerOperation,
  } as any;
}

function activeBudgetStatus(walletSigningSessionId: string, remainingUses: number = 10) {
  return {
    sessionId: walletSigningSessionId,
    status: 'active' as const,
    remainingUses,
    expiresAtMs: Date.now() + 60_000,
    projectionVersion: `projection:${walletSigningSessionId}:${remainingUses}`,
  };
}

function createActiveSigningSessionCoordinator(
  walletSigningSessionId: string,
  remainingUses: number = 10,
): SigningSessionCoordinator {
  return new SigningSessionCoordinator({
    getStatus: async () => activeBudgetStatus(walletSigningSessionId, remainingUses),
    consumeUse: async ({ uses }) =>
      activeBudgetStatus(walletSigningSessionId, Math.max(0, remainingUses - uses)),
  });
}

async function signTransactionsWithActions(args: any) {
  const nearAccountId = String(args.rpcCall?.nearAccountId || '').trim();
  const sessionId = String(args.sessionId || '').trim();
  const record = nearAccountId
    ? getStoredThresholdEd25519SessionRecordForAccount(nearAccountId)
    : null;
  const thresholdSessionId = sessionId || String(record?.thresholdSessionId || '').trim();
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  if (!nearAccountId || !thresholdSessionId || !walletSigningSessionId) {
    return await signPreparedTransactionsWithActions(args);
  }

  const authMethod = record?.source === 'email_otp' ? 'email_otp' : 'passkey';
  const signingLane =
    args.signingLane ??
    (authMethod === 'email_otp'
      ? buildNearTransactionSigningLane({
          accountId: nearAccountId,
          authMethod: 'email_otp',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          retention: record?.emailOtpAuthContext?.retention || 'session',
        })
      : buildNearTransactionSigningLane({
          accountId: nearAccountId,
          authMethod: 'passkey',
          walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
          thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          storageSource: record?.source && record.source !== 'email_otp' ? record.source : 'login',
        }));
  const requiresFreshAuth = args.emailOtpSigning || !String(record?.xClientBaseB64u || '').trim();
  const signingAuthPlan =
    args.signingAuthPlan ??
    (requiresFreshAuth
      ? authMethod === 'email_otp'
        ? { kind: 'emailOtpReauth', method: 'email_otp' }
        : { kind: 'passkeyReauth', method: 'passkey' }
      : {
          kind: 'warmSession',
          method: authMethod,
          accountId: nearAccountId,
          intent: 'transaction_sign',
          curve: 'ed25519',
          sessionId: thresholdSessionId,
          expiresAtMs: Math.floor(Number(record?.expiresAtMs) || Date.now() + 60_000),
          remainingUses: Math.max(1, Math.floor(Number(record?.remainingUses) || 1)),
        });
  const signingSessionPlan =
    args.signingSessionPlan ??
    (signingAuthPlan.kind === 'warmSession'
      ? {
          kind: SigningSessionPlanKind.WarmSession,
          lane: signingLane,
          keyRef: {
            kind: SigningKeyRefIntentKind.Cached,
            thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
          },
        }
      : signingAuthPlan.kind === 'emailOtpReauth'
        ? {
            kind: SigningSessionPlanKind.EmailOtpReauth,
            lane: signingLane,
            challenge: {
              chainFamily: 'near',
              lane: signingLane,
            },
          }
        : {
            kind: SigningSessionPlanKind.PasskeyReauth,
            lane: signingLane,
            reconnect: {
              lane: signingLane,
              thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
            },
          });
  const transactionLane = {
    accountId: nearAccountId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(thresholdSessionId),
  };
  const transactionOperation = args.transactionOperation ?? {
    intent: {
      walletId: nearAccountId,
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: { kind: 'account_class', authMethod },
      operationUsesNeeded: 1,
    },
    lane: transactionLane,
    readiness: {
      status: requiresFreshAuth ? 'auth_unavailable' : 'ready',
      ...(requiresFreshAuth
        ? { reason: 'fresh_auth_required' }
        : {
            remainingUses: Math.max(1, Math.floor(Number(record?.remainingUses) || 1)),
            expiresAtMs: Math.floor(Number(record?.expiresAtMs) || Date.now() + 60_000),
          }),
    },
  };
  const makeBudgetAdmittedOperation = (lane: any = transactionLane) => {
    const admittedWalletSigningSessionId = String(
      lane.walletSigningSessionId || walletSigningSessionId,
    );
    const budgetStatus = activeBudgetStatus(
      admittedWalletSigningSessionId,
      Math.max(1, Math.floor(Number(record?.remainingUses) || 1)),
    );
    return {
      ...transactionOperation,
      lane,
      budgetAdmission: {
        budgetIdentity: {
          walletSigningSessionId: admittedWalletSigningSessionId,
          projectionVersion: budgetStatus.projectionVersion,
          status: budgetStatus,
        },
      },
    };
  };
  const ed25519SigningBoundary = args.ed25519SigningBoundary || {
    sessionId: thresholdSessionId,
    signingSessionPlan,
    signingAuthPlan,
    signingLane,
    initialBudgetAdmittedOperation:
      signingAuthPlan.kind === 'warmSession' ? makeBudgetAdmittedOperation() : null,
  };

  return await signPreparedTransactionsWithActions({
    ...args,
    transactionOperation,
    ed25519SigningBoundary,
    signingSessionCoordinator:
      args.signingSessionCoordinator ||
      createActiveSigningSessionCoordinator(
        walletSigningSessionId,
        Math.max(1, Math.floor(Number(record?.remainingUses) || 1)),
      ),
  });
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
      let workerThresholdSessionAuthToken = '';
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
            keyMaterialStore: {
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
            claimWarmSessionMaterial: async () => {
              claimCalls += 1;
              return { ok: false as const, code: 'unexpected', message: 'should not claim' };
            },
            clearVolatileWarmSessionMaterial: async () => undefined,
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
            workerThresholdSessionAuthToken = String(
              request?.payload?.threshold?.thresholdSessionAuthToken || '',
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
        signingSessionCoordinator: createActiveSigningSessionCoordinator(
          walletSigningSessionId,
          10,
        ),
        onEvent: (event: any) => progressEvents.push(event),
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('warmSession');
      expect(claimCalls).toBe(0);
      expect(workerThresholdSessionAuthToken).toBe('email-otp-threshold-jwt');
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
      let workerThresholdSessionAuthToken = '';
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
            keyMaterialStore: {
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
            clearVolatileWarmSessionMaterial: async () => undefined,
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
            workerThresholdSessionAuthToken = String(
              request?.payload?.threshold?.thresholdSessionAuthToken || '',
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
        onEvent: (event: any) => {
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
          complete: async (authorization: any) => {
            completedOtpCode = String(authorization?.otpCode || '');
            persistWarmSessionEd25519Capability({
              kind: 'jwt_email_otp',
              sessionKind: 'jwt',
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
        signingSessionCoordinator: new SigningSessionCoordinator({
          getStatus: async () => activeBudgetStatus(walletSigningSessionId, 1),
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
              remainingUses: 0,
              projectionVersion: `projection:${walletSigningSessionId}:0`,
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
      expect(workerThresholdSessionAuthToken).toBe('email-otp-refreshed-threshold-jwt');
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
              keyMaterialStore: {
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
              clearVolatileWarmSessionMaterial: async () => undefined,
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

  test('uses persisted Ed25519 session material when the warm session cache is missing', async () => {
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
        kind: 'jwt_passkey',
        sessionKind: 'jwt',
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
      let workerThresholdSessionAuthToken = '';
      let workerCredentialJson = '';
      let workerXClientBaseB64u = '';

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
            keyMaterialStore: {
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
            claimWarmSessionMaterial: async () => {
              claimCalls += 1;
              return { ok: false as const, code: 'unexpected', message: 'should not claim' };
            },
            clearVolatileWarmSessionMaterial: async () => undefined,
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
            workerThresholdSessionAuthToken = String(
              request?.payload?.threshold?.thresholdSessionAuthToken || '',
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
        signingSessionCoordinator: createActiveSigningSessionCoordinator(
          walletSigningSessionId,
          10,
        ),
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('warmSession');
      expect(claimCalls).toBe(0);
      expect(workerThresholdSessionAuthToken).toBe('persisted-threshold-jwt');
      expect(workerCredentialJson).toBe('');
      expect(workerXClientBaseB64u).toBe('persisted-x-client-base');
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
      localStorage.setItem('seams:debug:signing-session', '1');
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
          kind: 'jwt_passkey',
          sessionKind: 'jwt',
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
        let preparedWebAuthnChallengeDigest = '';
        let reconnectSessionId = '';
        let reconnectWalletSigningSessionId = '';
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
              preparedWebAuthnChallengeDigest = String(
                params?.webauthnChallenge?.digest32B64u || '',
              ).trim();
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
            prepare: async () => ({
              sessionId: thresholdSessionId,
              walletSigningSessionId,
              sessionPolicyDigest32: 'planned-ed25519-session-policy-digest',
            }),
            reconnect: async (args: any) => {
              reconnectCalls += 1;
              reconnectSessionId = String(
                args.authorization?.plannedPasskeyReconnect?.sessionId || '',
              ).trim();
              reconnectWalletSigningSessionId = String(
                args.authorization?.plannedPasskeyReconnect?.walletSigningSessionId || '',
              ).trim();
              return { sessionId: thresholdSessionId };
            },
          },
          signingSessionCoordinator: createActiveSigningSessionCoordinator(
            walletSigningSessionId,
            10,
          ),
        });

        expect(signed).toHaveLength(1);
        expect(reconnectCalls).toBe(1);
        expect(preparedWebAuthnChallengeDigest).toBe('planned-ed25519-session-policy-digest');
        expect(reconnectSessionId).toBe(thresholdSessionId);
        expect(reconnectWalletSigningSessionId).toBe(walletSigningSessionId);
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

  test('syncs passkey Ed25519 step-up spend after the server consumes its single use', async () => {
    await withNearThresholdTestEnv(async () => {
      const nearAccountId = 'near-passkey-stepup-consumed.testnet';
      const thresholdSessionId = 'near-passkey-stepup-consumed-session';
      const walletSigningSessionId = 'wallet-near-passkey-stepup-consumed';
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

      const refreshedRecord = persistWarmSessionEd25519Capability({
        kind: 'jwt_passkey',
        sessionKind: 'jwt',
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
        jwt: 'near-passkey-stepup-consumed-threshold-jwt',
        xClientBaseB64u: 'near-passkey-stepup-consumed-x-client-base',
        source: 'registration',
      });

      let workerSigned = false;
      let consumeCalls = 0;
      const signingSessionCoordinator = new SigningSessionCoordinator({
        getStatus: async ({ targetThresholdSessionIds }: any) => {
          const targetIds = (targetThresholdSessionIds || []).map((id: string) =>
            String(id).replace(/^threshold-ed25519:/, ''),
          );
          if (workerSigned && targetIds.includes(thresholdSessionId)) {
            return {
              sessionId: walletSigningSessionId,
              status: 'exhausted' as const,
              remainingUses: 0,
              expiresAtMs: Date.now() + 60_000,
              projectionVersion: `projection:${walletSigningSessionId}:consumed`,
            };
          }
          return activeBudgetStatus(walletSigningSessionId, 1);
        },
        consumeUse: async ({ alreadyConsumedThresholdSessionIds }: any) => {
          consumeCalls += 1;
          expect(
            (alreadyConsumedThresholdSessionIds || []).map((id: string) =>
              String(id).replace(/^threshold-ed25519:/, ''),
            ),
          ).toContain(thresholdSessionId);
          return {
            sessionId: walletSigningSessionId,
            status: 'exhausted' as const,
            remainingUses: 0,
            expiresAtMs: Date.now() + 60_000,
            projectionVersion: `projection:${walletSigningSessionId}:consumed`,
          };
        },
      } as any);

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
          orchestrateSigningConfirmation: async () => ({
            intentDigest: 'intent-digest-b64u',
            transactionContext: {
              nearPublicKeyStr: 'ed25519:threshold-public-key',
              nextNonce: '1',
              txBlockHeight: '1',
              txBlockHash: 'blockhash',
              accessKeyInfo: { nonce: 0 },
            },
            credential: dummyCredential,
          }),
          requestWorkerOperation: async () => {
            workerSigned = true;
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
        signingAuthPlan: {
          kind: 'passkeyReauth',
          method: 'passkey',
        },
        signingLane,
        passkeyEd25519Reconnect: {
          prepare: async () => ({
            sessionId: thresholdSessionId,
            walletSigningSessionId,
            sessionPolicyDigest32: 'planned-ed25519-session-policy-digest',
          }),
          reconnect: async () => ({ sessionId: thresholdSessionId, record: refreshedRecord }),
        },
        signingSessionCoordinator,
      });

      expect(signed).toHaveLength(1);
      expect(consumeCalls).toBe(1);
    });
  });

  test('reuses caller-provided Ed25519 session-policy credential without another passkey prompt', async () => {
    await withNearThresholdTestEnv(async () => {
      const originalFetch = globalThis.fetch;
      const nearAccountId = 'near-passkey-reconnect-single-prompt.testnet';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const plannedSessionId = 'threshold-ed25519-planned-reconnect-session';
      const plannedWalletSigningSessionId = 'wallet-planned-reconnect-session';
      const credential = {
        id: 'session-policy-credential',
        rawId: 'session-policy-credential-raw',
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
      let promptCalls = 0;
      let mintBody: any = null;

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === `${relayerUrl}/threshold-ed25519/session`) {
          mintBody = JSON.parse(String(init?.body || '{}'));
          return new Response(
            JSON.stringify({
              ok: true,
              sessionId: plannedSessionId,
              walletSigningSessionId: plannedWalletSigningSessionId,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              remainingUses: 1,
              jwt: 'planned-threshold-jwt',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      try {
        const result = await connectEd25519Session({
          indexedDB: {} as any,
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              promptCalls += 1;
              throw new Error('unexpected second WebAuthn prompt');
            },
          },
          relayerUrl,
          relayerKeyId,
          nearAccountId,
          participantIds: [1, 2],
          sessionId: plannedSessionId,
          walletSigningSessionId: plannedWalletSigningSessionId,
          remainingUses: 1,
          auth: {
            kind: 'threshold_session_policy_webauthn',
            webauthnAuthentication: credential as any,
          },
        });

        expect(result.ok).toBe(true);
        expect(result.sessionId).toBe(plannedSessionId);
        expect(promptCalls).toBe(0);
        expect(mintBody?.sessionPolicy?.sessionId).toBe(plannedSessionId);
        expect(mintBody?.sessionPolicy?.walletSigningSessionId).toBe(plannedWalletSigningSessionId);
        expect(mintBody?.webauthn_authentication?.id).toBe('session-policy-credential');
        expect(mintBody?.webauthn_authentication?.clientExtensionResults?.prf).toBeUndefined();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  test('does not spend managed registration quota when Ed25519 unlock has app-session auth', async () => {
    await withNearThresholdTestEnv(async () => {
      const originalFetch = globalThis.fetch;
      const nearAccountId = 'near-ed25519-app-session-unlock.testnet';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const plannedSessionId = 'threshold-ed25519-app-session-unlock-session';
      const plannedWalletSigningSessionId = 'wallet-ed25519-app-session-unlock';
      const runtimePolicyScope = {
        orgId: 'org-runtime',
        projectId: 'project-runtime',
        envId: 'dev',
        signingRootVersion: 'v1',
      };
      const appSessionJwt = `header.${btoa(JSON.stringify({ runtimePolicyScope }))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '')}.sig`;
      const credential = {
        id: 'app-session-policy-credential',
        rawId: 'app-session-policy-credential-raw',
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
      const fetchUrls: string[] = [];
      let mintAuthorization = '';
      let mintBody: any = null;

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        fetchUrls.push(url);
        if (url === `${relayerUrl}/v1/registration/bootstrap-grants`) {
          throw new Error('unlock must not consume managed registration bootstrap grants');
        }
        if (url === `${relayerUrl}/threshold-ed25519/session`) {
          mintAuthorization = String(
            (init?.headers as Record<string, string>)?.Authorization || '',
          );
          mintBody = JSON.parse(String(init?.body || '{}'));
          return new Response(
            JSON.stringify({
              ok: true,
              sessionId: plannedSessionId,
              walletSigningSessionId: plannedWalletSigningSessionId,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              remainingUses: 3,
              runtimePolicyScope,
              jwt: 'app-session-threshold-jwt',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      try {
        const result = await connectEd25519Session({
          indexedDB: {} as any,
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              throw new Error('app-session unlock should not collect another WebAuthn prompt');
            },
          },
          relayerUrl,
          relayerKeyId,
          nearAccountId,
          participantIds: [1, 2],
          sessionId: plannedSessionId,
          walletSigningSessionId: plannedWalletSigningSessionId,
          remainingUses: 3,
          auth: {
            kind: 'app_session_jwt',
            appSessionJwt,
            localPrfCredential: credential as any,
          },
          runtimeScopeBootstrap: {
            environmentId: 'dev',
            publishableKey: 'pk_test_registration_quota',
          },
        });

        expect(result.ok).toBe(true);
        expect(fetchUrls).not.toContain(`${relayerUrl}/v1/registration/bootstrap-grants`);
        expect(fetchUrls).toContain(`${relayerUrl}/threshold-ed25519/session`);
        expect(mintAuthorization).toBe(`Bearer ${appSessionJwt}`);
        expect(mintBody?.runtimeEnvironmentId).toBe('dev');
        expect(mintBody?.sessionPolicy?.runtimePolicyScope).toEqual(runtimePolicyScope);
        expect(mintBody?.webauthn_authentication).toBeUndefined();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  test('does not spend managed registration quota when Ed25519 unlock relies on relay scope minting', async () => {
    await withNearThresholdTestEnv(async () => {
      const originalFetch = globalThis.fetch;
      const nearAccountId = 'near-ed25519-app-session-relay-scope.testnet';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const plannedSessionId = 'threshold-ed25519-relay-scope-session';
      const plannedWalletSigningSessionId = 'wallet-ed25519-relay-scope';
      const runtimePolicyScope = {
        orgId: 'org-runtime',
        projectId: 'project-runtime',
        envId: 'dev',
        signingRootVersion: 'v1',
      };
      const appSessionJwt = 'header.eyJzdWIiOiJhcHAtc2Vzc2lvbiJ9.sig';
      const credential = {
        id: 'relay-scope-policy-credential',
        rawId: 'relay-scope-policy-credential-raw',
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
      const fetchUrls: string[] = [];
      let mintAuthorization = '';
      let mintBody: any = null;

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        fetchUrls.push(url);
        if (url === `${relayerUrl}/v1/registration/bootstrap-grants`) {
          throw new Error('unlock must not consume managed registration bootstrap grants');
        }
        if (url === `${relayerUrl}/threshold-ed25519/session`) {
          mintAuthorization = String(
            (init?.headers as Record<string, string>)?.Authorization || '',
          );
          mintBody = JSON.parse(String(init?.body || '{}'));
          return new Response(
            JSON.stringify({
              ok: true,
              sessionId: plannedSessionId,
              walletSigningSessionId: plannedWalletSigningSessionId,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              remainingUses: 3,
              runtimePolicyScope,
              jwt: 'relay-scope-threshold-jwt',
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      try {
        const result = await connectEd25519Session({
          indexedDB: {} as any,
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              throw new Error('app-session unlock should not collect another WebAuthn prompt');
            },
          },
          relayerUrl,
          relayerKeyId,
          nearAccountId,
          participantIds: [1, 2],
          sessionId: plannedSessionId,
          walletSigningSessionId: plannedWalletSigningSessionId,
          remainingUses: 3,
          auth: {
            kind: 'app_session_jwt',
            appSessionJwt,
            localPrfCredential: credential as any,
          },
          runtimeScopeBootstrap: {
            environmentId: 'dev',
            publishableKey: 'pk_test_registration_quota',
          },
        });

        expect(result.ok).toBe(true);
        expect(fetchUrls).not.toContain(`${relayerUrl}/v1/registration/bootstrap-grants`);
        expect(fetchUrls).toContain(`${relayerUrl}/threshold-ed25519/session`);
        expect(mintAuthorization).toBe(`Bearer ${appSessionJwt}`);
        expect(result.runtimePolicyScope).toEqual(runtimePolicyScope);
        expect(mintBody?.runtimeEnvironmentId).toBe('dev');
        expect(mintBody?.sessionPolicy?.runtimePolicyScope).toBeUndefined();
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  });

  test('sends passkey assertion when minting an Ed25519 session as a cookie', async () => {
    await withNearThresholdTestEnv(async () => {
      const originalFetch = globalThis.fetch;
      const nearAccountId = 'near-ed25519-cookie-unlock.testnet';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const plannedSessionId = 'cookie-ed25519-session';
      const plannedWalletSigningSessionId = 'cookie-ed25519-wallet-session';
      const credential = {
        id: 'cookie-session-policy-credential',
        rawId: 'cookie-session-policy-credential',
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
      let mintCredentials = '';
      let mintBody: any = null;

      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === `${relayerUrl}/threshold-ed25519/session`) {
          mintCredentials = String(init?.credentials || '');
          mintBody = JSON.parse(String(init?.body || '{}'));
          return new Response(
            JSON.stringify({
              ok: true,
              sessionId: plannedSessionId,
              walletSigningSessionId: plannedWalletSigningSessionId,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              remainingUses: 2,
            }),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        }
        return await originalFetch(input, init);
      }) as typeof fetch;

      try {
        const result = await connectEd25519Session({
          indexedDB: {} as any,
          touchIdPrompt: {
            getRpId: () => 'example.localhost',
            getAuthenticationCredentialsSerializedForChallengeB64u: async () => {
              throw new Error('cookie unlock should reuse the login WebAuthn credential');
            },
          },
          relayerUrl,
          relayerKeyId,
          nearAccountId,
          participantIds: [1, 2],
          sessionId: plannedSessionId,
          walletSigningSessionId: plannedWalletSigningSessionId,
          remainingUses: 2,
          sessionKind: 'cookie',
          auth: {
            kind: 'threshold_session_policy_webauthn',
            webauthnAuthentication: credential as any,
          },
        });

        expect(result.ok).toBe(true);
        expect(mintCredentials).toBe('include');
        expect(mintBody?.sessionKind).toBe('cookie');
        expect(mintBody?.webauthn_authentication?.id).toBe('cookie-session-policy-credential');
        expect(mintBody?.webauthn_authentication?.clientExtensionResults?.prf).toBeUndefined();
      } finally {
        globalThis.fetch = originalFetch;
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
      const signingSessionCoordinator = new SigningSessionCoordinator({
        getStatus: async () => activeBudgetStatus(walletSigningSessionId, 10),
        consumeUse: async (input) => {
          consumeCalls.push(input);
          return {
            sessionId: walletSigningSessionId,
            status: 'active',
            authMethod: 'email_otp',
            retention: 'session',
            remainingUses: 9,
            projectionVersion: `projection:${walletSigningSessionId}:9`,
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
          signingSessionCoordinator,
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
            complete: async (authorization: any) => {
              completedOtpCode = String(authorization?.otpCode || '');
              return { sessionId: thresholdSessionId };
            },
          },
          signingSessionCoordinator: new SigningSessionCoordinator({
            getStatus: async () => activeBudgetStatus(walletSigningSessionId, 1),
            consumeUse: async (input) => {
              consumeCalls.push(input);
              return {
                sessionId: walletSigningSessionId,
                status: 'active',
                authMethod: 'email_otp',
                retention: 'single_use',
                remainingUses: 0,
                projectionVersion: `projection:${walletSigningSessionId}:0`,
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
          complete: async (authorization: any) => {
            completedOtpCode = String(authorization?.otpCode || '');
            completedChallengeId = String(authorization?.challengeId || '');
            persistWarmSessionEd25519Capability({
              kind: 'jwt_email_otp',
              sessionKind: 'jwt',
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
        signingSessionCoordinator: new SigningSessionCoordinator({
          getStatus: async () => activeBudgetStatus(walletSigningSessionId, 1),
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
              projectionVersion: `projection:${walletSigningSessionId}:0`,
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
        kind: 'jwt_email_otp',
        sessionKind: 'jwt',
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
          signingSessionCoordinator: new SigningSessionCoordinator({
            getStatus: async () => activeBudgetStatus(walletSigningSessionId, 10),
            consumeUse: async (input) => {
              consumeCalls.push(input);
              return {
                sessionId: walletSigningSessionId,
                status: 'active',
                authMethod: 'email_otp',
                retention: 'session',
                remainingUses: 9,
                projectionVersion: `projection:${walletSigningSessionId}:9`,
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

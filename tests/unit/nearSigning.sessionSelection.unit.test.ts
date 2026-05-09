import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WorkerResponseType } from '@/core/types/signer-worker';
import { signTransactionsWithActions } from '@/core/signingEngine/flows/signNear/signNear';
import {
  createNearSigningSessionCoordinator,
  buildNearThresholdSigningAuthPlan,
  resolveNearThresholdSigningAuthContext,
} from '@/core/signingEngine/flows/signNear/shared/thresholdAuthMode';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import type { AvailableSigningLanes } from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/session/persistence/records';

const TEST_ECDSA_CHAIN_TARGETS = {
  tempo: thresholdEcdsaChainTargetFromChainFamily({
    chain: 'tempo',
    chainId: 42431,
    networkSlug: 'tempo-testnet',
  }),
  evm: thresholdEcdsaChainTargetFromChainFamily({
    chain: 'evm',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  }),
};

function emptyEcdsaAvailableFields(): Pick<AvailableSigningLanes, 'ecdsa'> {
  const tempoLane = {
    curve: 'ecdsa' as const,
    chainTarget: TEST_ECDSA_CHAIN_TARGETS.tempo,
    state: 'missing' as const,
  };
  const evmLane = {
    curve: 'ecdsa' as const,
    chainTarget: TEST_ECDSA_CHAIN_TARGETS.evm,
    state: 'missing' as const,
  };
  return {
    ecdsa: {
      targets: [TEST_ECDSA_CHAIN_TARGETS.tempo, TEST_ECDSA_CHAIN_TARGETS.evm],
      lanesByTarget: {
        [thresholdEcdsaChainTargetKey(TEST_ECDSA_CHAIN_TARGETS.tempo)]: tempoLane,
        [thresholdEcdsaChainTargetKey(TEST_ECDSA_CHAIN_TARGETS.evm)]: evmLane,
      },
      candidatesByTarget: {
        [thresholdEcdsaChainTargetKey(TEST_ECDSA_CHAIN_TARGETS.tempo)]: [],
        [thresholdEcdsaChainTargetKey(TEST_ECDSA_CHAIN_TARGETS.evm)]: [],
      },
    },
  };
}

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

function createNearEd25519AvailableLanes(args: {
  nearAccountId: string;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state?: 'ready' | 'restorable';
  source?: 'runtime_session_record' | 'durable_sealed_record';
}): AvailableSigningLanes {
  const lane = {
    authMethod: args.authMethod,
    curve: 'ed25519' as const,
    chain: 'near' as const,
    state: args.state || 'ready' as const,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    source: args.source || 'runtime_session_record' as const,
  };
  const ecdsa = emptyEcdsaAvailableFields();
  return {
    walletId: args.nearAccountId,
    generation: Date.now(),
    ecdsa: ecdsa.ecdsa,
    lanes: {
      ed25519: { near: lane },
    },
    candidates: {
      ed25519: { near: [lane] },
    },
  };
}

function createBudgetBackedSigningSessionCoordinator(args: {
  walletSigningSessionId: string;
  activeRemainingUses: number;
  exhaustedThresholdSessionIds?: readonly string[];
  onGetStatus?: (statusArgs: any) => void;
}): SigningSessionCoordinator {
  const exhaustedThresholdSessionIds = new Set(args.exhaustedThresholdSessionIds || []);
  const normalizeThresholdSessionId = (sessionId: string): string =>
    sessionId.replace(/^threshold-ed25519:/, '');
  return new SigningSessionCoordinator({
    getStatus: async (statusArgs: any) => {
      args.onGetStatus?.(statusArgs);
      const walletSigningSessionId = String(
        statusArgs.walletSigningSessionId || args.walletSigningSessionId,
      );
      const targetThresholdIds = (statusArgs.targetThresholdSessionIds || []).map((sessionId: any) =>
        normalizeThresholdSessionId(String(sessionId)),
      );
      if (targetThresholdIds.some((sessionId: string) => exhaustedThresholdSessionIds.has(sessionId))) {
        return {
          sessionId: walletSigningSessionId,
          status: 'exhausted' as const,
          remainingUses: 0,
          projectionVersion: `projection:${walletSigningSessionId}:exhausted`,
        };
      }
      return {
        sessionId: walletSigningSessionId,
        status: 'active' as const,
        remainingUses: args.activeRemainingUses,
        expiresAtMs: Date.now() + 60_000,
        projectionVersion: `projection:${walletSigningSessionId}:${args.activeRemainingUses}`,
      };
    },
    consumeUse: async (consumeArgs: any) => ({
      sessionId: consumeArgs.walletSigningSessionId,
      status: 'active' as const,
      remainingUses: Math.max(0, args.activeRemainingUses - consumeArgs.uses),
      expiresAtMs: Date.now() + 60_000,
      projectionVersion: `projection:${consumeArgs.walletSigningSessionId}:consumed`,
    }),
  } as any);
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

    let seenThresholdSessionAuthToken = '';

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
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId: 'wallet-signing-session',
            activeRemainingUses: 10,
          }),
          resolveThresholdEd25519SessionId: () => 'ed25519-session',
          readAvailableSigningLanesForSigning: async () =>
            createNearEd25519AvailableLanes({
              nearAccountId: 'alice.testnet',
              authMethod: 'passkey',
              walletSigningSessionId: 'wallet-signing-session',
              thresholdSessionId: 'ed25519-session',
            }),
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
                getWarmSessionStatus: async () => ({
                  ok: false as const,
                  code: 'not_found',
                  message: 'warm-session status missing',
                }),
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
                seenThresholdSessionAuthToken = String(
                  request?.payload?.threshold?.thresholdSessionAuthToken || '',
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
      expect(seenThresholdSessionAuthToken).toBe('persisted-threshold-jwt');
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

  test('uses the prepared warm Ed25519 plan without re-planning after confirmation starts', async () => {
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

      const nearAccountId = 'prepared-warm-plan.testnet';
      const sessionId = 'prepared-warm-ed25519-session';
      const walletSigningSessionId = 'wallet-prepared-warm-ed25519';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      let confirmationCount = 0;

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId: 'example.localhost',
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        sessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 4,
        jwt: 'prepared-warm-threshold-jwt',
        xClientBaseB64u: 'prepared-warm-client-base',
        source: 'registration',
      });

      const result = await signTransactionsWithActions(
        {
          nearRpcUrl: 'https://rpc.example.test',
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 4,
          }),
          resolveThresholdEd25519SessionId: () => sessionId,
          readAvailableSigningLanesForSigning: async () =>
            createNearEd25519AvailableLanes({
              nearAccountId,
              authMethod: 'passkey',
              walletSigningSessionId,
              thresholdSessionId: sessionId,
            }),
          createSigningSessionId: () => 'unexpected-generated-session',
          getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => ({
            sessionId: thresholdSessionId,
            status: 'active',
            remainingUses: 4,
            expiresAtMs: Date.now() + 60_000,
          }),
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-prepared-warm',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-prepared-warm',
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
                getRpId: () => 'example.localhost',
              },
              relayerUrl,
              touchConfirm: {
                getWarmSessionStatus: async () => {
                  throw new Error('transaction executor re-planned after receiving a prepared lane');
                },
                claimWarmSessionMaterial: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not claim with cached client base',
                }),
                clearWarmSessionMaterial: async () => undefined,
                orchestrateSigningConfirmation: async (params: any) => {
                  confirmationCount += 1;
                  expect(params?.signingAuthPlan?.kind).toBe('warmSession');
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
            }) as any,
          withThresholdEd25519CommitQueue: async ({ task }) => await task(),
        },
        {
          rpcCall: { nearAccountId, nearRpcUrl: 'https://rpc.testnet.test' },
          signerSlot: 1,
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(confirmationCount).toBe(1);
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
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 1,
            exhaustedThresholdSessionIds: [staleSessionId],
            onGetStatus: (statusArgs) => {
              const targetThresholdIds = (statusArgs.targetThresholdSessionIds || []).map(
                (sessionId: any) => String(sessionId).replace(/^threshold-ed25519:/, ''),
              );
              if (targetThresholdIds.includes(refreshedSessionId)) {
                order.push('budget');
              }
            },
          }),
          resolveThresholdEd25519SessionId: () => staleSessionId,
          readAvailableSigningLanesForSigning: async () =>
            createNearEd25519AvailableLanes({
              nearAccountId,
              authMethod: 'email_otp',
              walletSigningSessionId,
              thresholdSessionId: staleSessionId,
            }),
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
                order.push('worker');
                workerSessionId = String(request?.sessionId || '').trim();
                expect(String(request?.payload?.threshold?.thresholdSessionAuthToken || '')).toBe(
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
      expect(order.slice(0, 6)).toEqual([
        'display',
        'challenge',
        'confirm',
        'complete:246810',
        'budget',
        'worker',
      ]);
      expect(order.indexOf('budget')).toBeLessThan(order.indexOf('worker'));
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

  test('restores only Email OTP Ed25519 lane for OTP account when passkey runtime state is stale', async () => {
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

      const nearAccountId = 'otp-missing-runtime-restore.testnet';
      const restoredSessionId = 'otp-missing-runtime-restored-session';
      const refreshedSessionId = 'otp-missing-runtime-refreshed-session';
      const walletSigningSessionId = 'wallet-otp-missing-runtime';
      const stalePasskeySessionId = 'otp-missing-runtime-stale-passkey-session';
      const stalePasskeyWalletSessionId = 'wallet-otp-missing-runtime-stale-passkey';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const restoreCalls: string[] = [];

      const persistEmailOtpRecord = (sessionId: string, jwt: string, remainingUses: number) =>
        persistWarmSessionEd25519Capability({
          nearAccountId,
          rpId,
          relayerUrl,
          relayerKeyId,
          participantIds: [1, 2],
          sessionId,
          walletSigningSessionId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses,
          jwt,
          xClientBaseB64u: `${sessionId}-client-base`,
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
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 3,
            exhaustedThresholdSessionIds: [restoredSessionId],
          }),
          resolveAccountAuthMethodForSigning: async () => 'email_otp',
          readAvailableSigningLanesForSigning: async ({ authMethod }) => {
            expect(authMethod === undefined || authMethod === null || authMethod === 'email_otp')
              .toBe(true);
            const ecdsa = emptyEcdsaAvailableFields();
            return {
              walletId: nearAccountId,
              generation: Date.now(),
              ecdsa: ecdsa.ecdsa,
              lanes: {
                ed25519: {
                  near: {
                    authMethod: 'email_otp' as const,
                    curve: 'ed25519' as const,
                    chain: 'near' as const,
                    state: 'restorable' as const,
                    source: 'durable_sealed_record' as const,
                    walletSigningSessionId,
                    thresholdSessionId: restoredSessionId,
                  },
                },
              },
              candidates: {
                ed25519: {
                  near: [
                    {
                      authMethod: 'passkey' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'ready' as const,
                      source: 'runtime_session_record' as const,
                      walletSigningSessionId: stalePasskeyWalletSessionId,
                      thresholdSessionId: stalePasskeySessionId,
                    },
                    {
                      authMethod: 'email_otp' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'restorable' as const,
                      source: 'durable_sealed_record' as const,
                      walletSigningSessionId,
                      thresholdSessionId: restoredSessionId,
                    },
                  ],
                },
              },
            };
          },
          restorePersistedSessionForSigning: async ({
            authMethod,
            walletSigningSessionId: restoredWalletSigningSessionId,
            thresholdSessionId,
          }) => {
            restoreCalls.push(authMethod);
            if (authMethod !== 'email_otp') {
              throw new Error(`unexpected ${authMethod} restore`);
            }
            expect(restoredWalletSigningSessionId).toBe(walletSigningSessionId);
            expect(thresholdSessionId).toBe(restoredSessionId);
            persistEmailOtpRecord(restoredSessionId, 'otp-missing-runtime-restored-jwt', 1);
          },
          getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => {
            const rawSessionId = String(thresholdSessionId).replace(/^threshold-ed25519:/, '');
            return {
              sessionId: thresholdSessionId,
              status: 'active' as const,
              remainingUses: rawSessionId === restoredSessionId ? 0 : 3,
              expiresAtMs: Date.now() + 60_000,
            };
          },
          requestEmailOtpTransactionSigningChallenge: async () => ({
            challengeId: 'otp-missing-runtime-challenge',
            emailHint: 'a***e@example.com',
          }),
          loginWithEmailOtpEd25519CapabilityForSigning: async ({ otpCode, remainingUses }) => {
            expect(otpCode).toBe('246810');
            expect(remainingUses).toBe(1);
            const record = persistEmailOtpRecord(
              refreshedSessionId,
              'otp-missing-runtime-refreshed-jwt',
              1,
            );
            return { sessionId: refreshedSessionId, record };
          },
          createSigningSessionId: () => 'unexpected-generated-session',
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-otp-missing-runtime',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-otp-missing-runtime',
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
                  expect(params?.emailOtpPrompt?.challengeId).toBe(
                    'otp-missing-runtime-challenge',
                  );
                  expect(params?.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.EmailOtpReauth);
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
                    emailOtpChallengeId: 'otp-missing-runtime-challenge',
                    credential: undefined,
                  };
                },
              },
              requestWorkerOperation: async ({ request }: any) => {
                expect(String(request?.sessionId || '')).toBe(refreshedSessionId);
                expect(String(request?.payload?.threshold?.thresholdSessionAuthToken || '')).toBe(
                  'otp-missing-runtime-refreshed-jwt',
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
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(restoreCalls).toEqual(['email_otp']);
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

  test('restores durable Ed25519 lane with valid budget and signs without step-up', async () => {
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

      const nearAccountId = 'durable-ed25519-valid-budget.testnet';
      const restoredSessionId = 'durable-ed25519-restored-session';
      const walletSigningSessionId = 'wallet-durable-ed25519-valid-budget';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const restoreCalls: any[] = [];
      const confirmationAuthPlans: string[] = [];
      const emailOtpPrompts: string[] = [];
      let workerSessionId = '';

      const result = await signTransactionsWithActions(
        {
          nearRpcUrl: 'https://rpc.example.test',
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 3,
          }),
          createSigningSessionId: () => 'unexpected-generated-session',
          resolveAccountAuthMethodForSigning: async () => 'email_otp',
          readAvailableSigningLanesForSigning: async ({ authMethod }) => {
            expect(authMethod === undefined || authMethod === null || authMethod === 'email_otp')
              .toBe(true);
            const ecdsa = emptyEcdsaAvailableFields();
            return {
              walletId: nearAccountId,
              generation: Date.now(),
              ecdsa: ecdsa.ecdsa,
              lanes: {
                ed25519: {
                  near: {
                    authMethod: 'email_otp' as const,
                    curve: 'ed25519' as const,
                    chain: 'near' as const,
                    state: 'restorable' as const,
                    source: 'durable_sealed_record' as const,
                    walletSigningSessionId,
                    thresholdSessionId: restoredSessionId,
                  },
                },
              },
              candidates: {
                ed25519: {
                  near: [
                    {
                      authMethod: 'email_otp' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'restorable' as const,
                      source: 'durable_sealed_record' as const,
                      walletSigningSessionId,
                      thresholdSessionId: restoredSessionId,
                    },
                  ],
                },
              },
            };
          },
          restorePersistedSessionForSigning: async (restoreArgs) => {
            restoreCalls.push({
              authMethod: restoreArgs.authMethod,
              walletSigningSessionId: restoreArgs.walletSigningSessionId,
              thresholdSessionId: restoreArgs.thresholdSessionId,
            });
            persistWarmSessionEd25519Capability({
              nearAccountId,
              rpId,
              relayerUrl,
              relayerKeyId,
              participantIds: [1, 2],
              sessionId: restoredSessionId,
              walletSigningSessionId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
              jwt: 'durable-ed25519-restored-jwt',
              xClientBaseB64u: 'durable-ed25519-restored-client-base',
              source: 'email_otp',
              emailOtpAuthContext: {
                policy: 'session',
                retention: 'session',
                reason: 'login',
                authMethod: 'email_otp',
              },
            });
          },
          getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => ({
            sessionId: thresholdSessionId,
            status: 'active' as const,
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          }),
          requestEmailOtpTransactionSigningChallenge: async () => {
            throw new Error('valid restored budget must not prompt Email OTP');
          },
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-durable-ed25519-valid-budget',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-durable-ed25519-valid-budget',
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
                  confirmationAuthPlans.push(String(params?.signingAuthPlan?.kind || ''));
                  emailOtpPrompts.push(String(params?.emailOtpPrompt?.challengeId || ''));
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
                workerSessionId = String(request?.sessionId || '').trim();
                expect(String(request?.payload?.threshold?.thresholdSessionAuthToken || '')).toBe(
                  'durable-ed25519-restored-jwt',
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
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(workerSessionId).toBe(restoredSessionId);
      expect(confirmationAuthPlans).toEqual([SigningAuthPlanKind.WarmSession]);
      expect(emailOtpPrompts).toEqual(['']);
      expect(restoreCalls).toEqual([
        {
          authMethod: 'email_otp',
          walletSigningSessionId,
          thresholdSessionId: restoredSessionId,
        },
      ]);
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

  test('keeps Ed25519 available-lane selection on the current OTP runtime record when account auth points at passkey', async () => {
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

      const nearAccountId = 'otp-runtime-candidate-selection.testnet';
      const currentSessionId = 'zzz-current-runtime-session';
      const otherDurableSessionId = 'aaa-other-durable-session';
      const passkeyDurableSessionId = 'passkey-other-durable-session';
      const walletSigningSessionId = 'wallet-otp-runtime-candidate-selection';
      const passkeyWalletSigningSessionId = 'wallet-passkey-runtime-candidate-selection';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const restoreCalls: string[] = [];
      let workerSessionId = '';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        sessionId: currentSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'otp-runtime-candidate-current-jwt',
        xClientBaseB64u: 'otp-runtime-candidate-current-client-base',
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
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 1,
          }),
          resolveAccountAuthMethodForSigning: async () => 'passkey',
          readAvailableSigningLanesForSigning: async ({ authMethod }) => {
            expect(authMethod).toBeUndefined();
            const ecdsa = emptyEcdsaAvailableFields();
            return {
              walletId: nearAccountId,
              generation: Date.now(),
              ecdsa: ecdsa.ecdsa,
              lanes: {
                ed25519: {
                  near: {
                    authMethod: 'email_otp' as const,
                    curve: 'ed25519' as const,
                    chain: 'near' as const,
                    state: 'restorable' as const,
                    source: 'durable_sealed_record' as const,
                    walletSigningSessionId,
                    thresholdSessionId: otherDurableSessionId,
                  },
                },
              },
              candidates: {
                ed25519: {
                  near: [
                    {
                      authMethod: 'email_otp' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'restorable' as const,
                      source: 'durable_sealed_record' as const,
                      walletSigningSessionId,
                      thresholdSessionId: otherDurableSessionId,
                    },
                    {
                      authMethod: 'passkey' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'restorable' as const,
                      source: 'durable_sealed_record' as const,
                      walletSigningSessionId: passkeyWalletSigningSessionId,
                      thresholdSessionId: passkeyDurableSessionId,
                    },
                    {
                      authMethod: 'email_otp' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'ready' as const,
                      source: 'runtime_session_record' as const,
                      walletSigningSessionId,
                      thresholdSessionId: currentSessionId,
                    },
                  ],
                },
              },
            };
          },
          restorePersistedSessionForSigning: async ({ thresholdSessionId }) => {
            restoreCalls.push(String(thresholdSessionId || ''));
          },
          getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => ({
            sessionId: thresholdSessionId,
            status: 'active' as const,
            remainingUses: 1,
            expiresAtMs: Date.now() + 60_000,
          }),
          createSigningSessionId: () => 'unexpected-generated-session',
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-otp-runtime-candidate-selection',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-otp-runtime-candidate-selection',
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
                orchestrateSigningConfirmation: async () => ({
                  intentDigest: 'intent-digest-b64u',
                  transactionContext: {
                    nearPublicKeyStr: 'ed25519:threshold-public-key',
                    nextNonce: '1',
                    txBlockHeight: '1',
                    txBlockHash: 'blockhash',
                    accessKeyInfo: { nonce: 0 },
                  },
                  credential: undefined,
                }),
              },
              requestWorkerOperation: async ({ request }: any) => {
                workerSessionId = String(request?.sessionId || '').trim();
                expect(String(request?.payload?.threshold?.thresholdSessionAuthToken || '')).toBe(
                  'otp-runtime-candidate-current-jwt',
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
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(workerSessionId).toBe(currentSessionId);
      expect(restoreCalls).toEqual([]);
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

  test('does not use the account runtime record when available signing lanes omit an exact Ed25519 lane', async () => {
    const originalSessionStorage = (globalThis as { sessionStorage?: Storage }).sessionStorage;
    const sessionStorage = new MemorySessionStorage();
    (
      globalThis as {
        sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'>;
      }
    ).sessionStorage = sessionStorage;

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const nearAccountId = 'otp-runtime-candidate-missing.testnet';
      const currentSessionId = 'otp-runtime-candidate-missing-current';
      const otherSessionId = 'otp-runtime-candidate-missing-other';
      const walletSigningSessionId = 'wallet-otp-runtime-candidate-missing';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const restoreCalls: string[] = [];
      let workerSessionId = '';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        sessionId: currentSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'otp-runtime-candidate-missing-current-jwt',
        xClientBaseB64u: 'otp-runtime-candidate-missing-current-client-base',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
        },
      });

      await expect(
        signTransactionsWithActions(
          {
            nearRpcUrl: 'https://rpc.example.test',
            signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
              walletSigningSessionId,
              activeRemainingUses: 1,
            }),
            createSigningSessionId: () => 'unexpected-generated-session',
            resolveAccountAuthMethodForSigning: async () => 'email_otp',
            readAvailableSigningLanesForSigning: async ({ authMethod }) => {
              expect(authMethod).toBeUndefined();
              const ecdsa = emptyEcdsaAvailableFields();
              return {
                walletId: nearAccountId,
                generation: Date.now(),
                ecdsa: ecdsa.ecdsa,
                lanes: {
                  ed25519: {
                    near: {
                      authMethod: 'email_otp' as const,
                      curve: 'ed25519' as const,
                      chain: 'near' as const,
                      state: 'restorable' as const,
                      source: 'durable_sealed_record' as const,
                      walletSigningSessionId,
                      thresholdSessionId: otherSessionId,
                    },
                  },
                },
                candidates: {
                  ed25519: {
                    near: [],
                  },
                },
              };
            },
            restorePersistedSessionForSigning: async ({ thresholdSessionId }) => {
              restoreCalls.push(String(thresholdSessionId || ''));
            },
            getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => ({
              sessionId: thresholdSessionId,
              status: 'active' as const,
              remainingUses: 1,
              expiresAtMs: Date.now() + 60_000,
            }),
            getSignerWorkerContext: () =>
            ({
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-otp-runtime-candidate-missing',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-otp-runtime-candidate-missing',
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
                  ok: true as const,
                  remainingUses: 1,
                  expiresAtMs: Date.now() + 60_000,
                }),
                claimWarmSessionMaterial: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not claim',
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
                  credential: undefined,
                }),
              },
              requestWorkerOperation: async ({ request }: any) => {
                workerSessionId = String(request?.sessionId || '').trim();
                expect(String(request?.payload?.threshold?.thresholdSessionAuthToken || '')).toBe(
                  'otp-runtime-candidate-missing-current-jwt',
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
            transactions: [
              {
                receiverId: nearAccountId,
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
          },
        ),
      ).rejects.toThrow('Ed25519 transaction signing requires an exact selected lane');
      expect(workerSessionId).toBe('');
      expect(restoreCalls).toEqual([]);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      sessionStorage.clear();
      if (originalSessionStorage) {
        (globalThis as { sessionStorage?: Storage }).sessionStorage = originalSessionStorage;
      } else {
        delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
      }
    }
  });

  test('retries Ed25519 transaction signing with Email OTP when stale auth fails after confirmation', async () => {
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

      const nearAccountId = 'otp-post-confirm-retry.testnet';
      const staleSessionId = 'otp-post-confirm-retry-stale-session';
      const refreshedSessionId = 'otp-post-confirm-retry-refreshed-session';
      const walletSigningSessionId = 'wallet-otp-post-confirm-retry';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';
      const order: string[] = [];
      let workerAttempts = 0;

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        sessionId: staleSessionId,
        walletSigningSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'otp-post-confirm-retry-stale-jwt',
        xClientBaseB64u: 'otp-post-confirm-retry-stale-client-base',
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
          signingSessionCoordinator: createBudgetBackedSigningSessionCoordinator({
            walletSigningSessionId,
            activeRemainingUses: 1,
          }),
          resolveThresholdEd25519SessionId: () => staleSessionId,
          readAvailableSigningLanesForSigning: async () =>
            createNearEd25519AvailableLanes({
              nearAccountId,
              authMethod: 'email_otp',
              walletSigningSessionId,
              thresholdSessionId: staleSessionId,
            }),
          getWarmThresholdEd25519SessionStatusForSession: async ({ thresholdSessionId }) => ({
            sessionId: thresholdSessionId,
            status: 'active',
            remainingUses: 1,
            expiresAtMs: Date.now() + 60_000,
          }),
          requestEmailOtpTransactionSigningChallenge: async () => {
            order.push('challenge');
            return {
              challengeId: 'otp-post-confirm-retry-challenge',
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
              sessionId: refreshedSessionId,
              walletSigningSessionId,
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 1,
              jwt: 'otp-post-confirm-retry-refreshed-jwt',
              xClientBaseB64u: 'otp-post-confirm-retry-refreshed-client-base',
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
                    profileId: 'profile-otp-post-confirm-retry',
                    accountRef: {
                      chainIdKey: 'near:testnet',
                      accountAddress: nearAccountId,
                    },
                  }),
                },
                accountKeyMaterialDB: {
                  getKeyMaterial: async () => ({
                    profileId: 'profile-otp-post-confirm-retry',
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
                  ok: true as const,
                  remainingUses: 1,
                  expiresAtMs: Date.now() + 60_000,
                }),
                claimWarmSessionMaterial: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not claim',
                }),
                clearWarmSessionMaterial: async () => undefined,
                orchestrateSigningConfirmation: async (params: any) => {
                  order.push(params?.emailOtpPrompt ? 'confirm:otp' : 'confirm:warm');
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
                    emailOtpChallengeId: 'otp-post-confirm-retry-challenge',
                    credential: undefined,
                  };
                },
              },
              requestWorkerOperation: async ({ request }: any) => {
                workerAttempts += 1;
                const requestSessionId = String(request?.sessionId || '').trim();
                if (workerAttempts === 1) {
                  expect(requestSessionId).toBe(staleSessionId);
                  throw new Error(
                    '[chains] threshold signingSession auth is unavailable; reconnect threshold session before signing',
                  );
                }
                expect(requestSessionId).toBe(refreshedSessionId);
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
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
          ],
        },
      );

      expect(result).toHaveLength(1);
      expect(workerAttempts).toBe(2);
      expect(order).toEqual(['confirm:warm', 'challenge', 'confirm:otp', 'complete:246810']);
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

  test('treats passkey Ed25519 auth-missing state as step-up reauthable', async () => {
    const nearAccountId = 'passkey-ed25519-auth-missing.testnet';
    const walletSigningSessionId = 'wallet-passkey-ed25519-auth-missing';
    const thresholdSessionId = 'threshold-passkey-ed25519-auth-missing';
    const expiresAtMs = Date.now() + 60_000;
    const warmSessionReader = {
      getWarmSession: async () => ({
        accountId: nearAccountId,
        updatedAtMs: Date.now(),
        capabilities: {
          ed25519: {
            capability: 'ed25519',
            state: 'auth_missing',
            record: {
              nearAccountId,
              rpId: 'example.localhost',
              relayerUrl: 'https://relay.example.test',
              relayerKeyId: 'ed25519:relayer-key-id',
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId,
              walletSigningSessionId,
              expiresAtMs,
              remainingUses: 0,
              source: 'login',
              updatedAtMs: Date.now(),
            },
            auth: null,
            prfClaim: null,
          },
          ecdsa: {
            evm: { capability: 'ecdsa', chain: 'evm', state: 'missing', record: null, auth: null, prfClaim: null },
            tempo: { capability: 'ecdsa', chain: 'tempo', state: 'missing', record: null, auth: null, prfClaim: null },
          },
        },
      }),
      getEd25519SigningSessionStatusForSession: async () => ({
        sessionId: thresholdSessionId,
        status: 'unavailable',
        statusCode: 'auth_missing',
      }),
    } as any;

    const context = await resolveNearThresholdSigningAuthContext({
      warmSessionReader,
      nearAccountId,
      operationLabel: 'transaction signing',
      usesNeeded: 1,
    });
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: walletSigningSessionId,
        status: 'active',
        remainingUses: 1,
        expiresAtMs,
        projectionVersion: 'projection:passkey-ed25519-auth-missing',
      }),
    } as any);
    const resolved = await coordinator.resolveAuthPlanFromReadiness(context.coordinatorInput);
    const plan = buildNearThresholdSigningAuthPlan({ context, resolvedSigningSession: resolved });

    expect(plan.signingAuthPlan?.kind).toBe(SigningAuthPlanKind.PasskeyReauth);
    expect(plan.warmSessionReady).toBe(false);
  });

  test('does not double-consume passkey Ed25519 material immediately after sealed restore', async () => {
    const consumeFlags: Array<boolean | undefined> = [];
    const restoreCalls: string[] = [];
    let statusOk = false;
    const coordinator = createNearSigningSessionCoordinator({
      getWarmSessionStatus: async () =>
        statusOk
          ? { ok: true as const, remainingUses: 2, expiresAtMs: Date.now() + 60_000 }
          : { ok: false as const, code: 'not_found', message: 'missing before restore' },
      getWarmSessionStatuses: async ({ sessionIds }: { sessionIds: string[] }) => ({
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: statusOk
            ? { ok: true as const, remainingUses: 2, expiresAtMs: Date.now() + 60_000 }
            : { ok: false as const, code: 'not_found', message: 'missing before restore' },
        })),
      }),
      restorePersistedSessionForSigning: async ({ thresholdSessionId }: any) => {
        restoreCalls.push(String(thresholdSessionId));
        statusOk = true;
      },
      claimWarmSessionMaterial: async ({ consume }: { consume?: boolean }) => {
        consumeFlags.push(consume);
        return {
          ok: true as const,
          prfFirstB64u: 'AQ',
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    } as any);

    await coordinator.claimPrfFirstByThresholdSessionId({
      thresholdSessionId: 'restored-passkey-ed25519',
      errorContext: 'test restored Ed25519 signing',
      uses: 1,
      walletId: 'alice.testnet',
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session',
    });
    await coordinator.claimPrfFirstByThresholdSessionId({
      thresholdSessionId: 'restored-passkey-ed25519',
      errorContext: 'test hot Ed25519 signing',
      uses: 1,
      walletId: 'alice.testnet',
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: 'wallet-session',
    });

    expect(restoreCalls).toEqual(['restored-passkey-ed25519', 'restored-passkey-ed25519']);
    expect(consumeFlags).toEqual([false, true]);
  });
});

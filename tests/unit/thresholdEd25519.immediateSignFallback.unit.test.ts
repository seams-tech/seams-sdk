import { expect, test } from '@playwright/test';
import { signTransactionsWithActions } from '@/core/signingEngine/orchestration/near/transactionsFlow';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSessionPersistence';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordForAccount,
  markThresholdEd25519EmailOtpSessionConsumedForAccount,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { ActionType } from '@/core/types/actions';
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
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
        sessionId,
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
          stepUpRequired: false,
        },
      });

      let resolvedSigningAuthMode = '';
      let resolvedSigningAuthPlanKind = '';
      let claimCalls = 0;
      let workerThresholdSessionJwt = '';
      let workerCredentialJson = '';
      let workerXClientBaseB64u = '';

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
        rpcCall: { nearAccountId },
        signerSlot: 1,
        sessionId,
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('warmSession');
      expect(claimCalls).toBe(0);
      expect(workerThresholdSessionJwt).toBe('email-otp-threshold-jwt');
      expect(workerCredentialJson).toBe('');
      expect(workerXClientBaseB64u).toBe('email-otp-x-client-base');
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
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
        sessionId: staleSessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 1,
        jwt: 'email-otp-stale-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'per_operation',
          retention: 'single_use',
          reason: 'sign',
          authMethod: 'email_otp',
          stepUpRequired: true,
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
        rpcCall: { nearAccountId },
        signerSlot: 1,
        sessionId: staleSessionId,
        emailOtpSigning: {
          challengeId: 'near-email-otp-challenge',
          emailHint: 'a***e@example.com',
          complete: async (otpCode: string) => {
            completedOtpCode = otpCode;
            persistWarmSessionEd25519Capability({
              nearAccountId,
              rpId,
              relayerUrl,
              relayerKeyId,
              participantIds: [1, 2],
              runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
              sessionId: refreshedSessionId,
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
                stepUpRequired: true,
              },
            });
            return { sessionId: refreshedSessionId };
          },
          markConsumed: (thresholdSessionId?: string) =>
            markThresholdEd25519EmailOtpSessionConsumedForAccount({
              nearAccountId,
              ...(thresholdSessionId ? { thresholdSessionId } : {}),
            }),
        },
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('');
      expect(resolvedSigningAuthPlanKind).toBe('emailOtpReauth');
      expect(capturedChallengeId).toBe('near-email-otp-challenge');
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
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
        sessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'email-otp-threshold-jwt',
        source: 'email_otp',
        emailOtpAuthContext: {
          policy: 'session',
          retention: 'session',
          reason: 'login',
          authMethod: 'email_otp',
          stepUpRequired: false,
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
          rpcCall: { nearAccountId },
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
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

      persistWarmSessionEd25519Capability({
        nearAccountId,
        rpId,
        relayerUrl,
        relayerKeyId,
        participantIds: [1, 2],
        runtimePolicyScope: { orgId: 'org-test', projectId: 'project-test', envId: 'dev' },
        sessionId,
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
        rpcCall: { nearAccountId },
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
});

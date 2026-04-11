import { expect, test } from '@playwright/test';
import { signTransactionsWithActions } from '@/core/signingEngine/orchestration/near/transactionsFlow';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmSessionPersistence';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
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
        sessionId,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'persisted-threshold-jwt',
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
                deviceNumber: 1,
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
        deviceNumber: 1,
        sessionId,
      });

      expect(Array.isArray(signed)).toBe(true);
      expect(signed).toHaveLength(1);
      expect(resolvedSigningAuthMode).toBe('webauthn');
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

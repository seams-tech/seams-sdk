import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { WorkerResponseType } from '@/core/types/signer-worker';
import { signTransactionsWithActions } from '@/core/signingEngine/api/nearSigning';
import {
  buildAndCacheEd25519AuthSession,
  clearAllCachedEd25519AuthSessions,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';

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

    clearAllCachedEd25519AuthSessions();

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

      await buildAndCacheEd25519AuthSession({
        nearAccountId: 'alice.testnet',
        rpId: 'example.localhost',
        relayerUrl: 'https://relay.example.test',
        relayerKeyId: 'ed25519:relayer-key-id',
        participantIds: [1, 2],
        sessionId: 'ed25519-session',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 10,
        jwt: 'persisted-threshold-jwt',
        source: 'registration',
      });
      clearAllCachedEd25519AuthSessions();

      const result = await signTransactionsWithActions(
        {
          nearRpcUrl: 'https://rpc.example.test',
          resolveCanonicalThresholdEd25519SessionId: () => 'ed25519-session',
          getOrCreateActiveThresholdEd25519SessionId: () => 'ecdsa-session',
          createSigningSessionId: () => 'unexpected-generated-session',
          getSignerWorkerContext: () =>
            ({
              indexedDB: {
                getNearThresholdKeyMaterial: async () => ({
                  nearAccountId: 'alice.testnet',
                  deviceNumber: 1,
                  kind: 'threshold_ed25519_v1' as const,
                  publicKey: 'ed25519:threshold-public-key',
                  relayerKeyId: 'ed25519:relayer-key-id',
                  keyVersion: 'threshold-ed25519-hss-v1',
                  timestamp: Date.now(),
                  participants: [
                    { id: 1, role: 'client' },
                    {
                      id: 2,
                      role: 'relayer',
                      relayerUrl: 'https://relay.example.test',
                      relayerKeyId: 'ed25519:relayer-key-id',
                    },
                  ],
                }),
              },
              nonceManager: {
                initializeUser: () => undefined,
              },
              touchIdPrompt: {
                getRpId: () => 'example.localhost',
              },
              relayerUrl: 'https://relay.example.test',
              touchConfirm: {
                peekPrfFirstForThresholdSession: async ({ sessionId }: { sessionId: string }) => {
                  seenSessionId = String(sessionId || '').trim();
                  return { ok: false as const, code: 'not_found', message: 'warm cache missing' };
                },
                dispensePrfFirstForThresholdSession: async () => ({
                  ok: false as const,
                  code: 'unexpected',
                  message: 'should not dispense',
                }),
                clearPrfFirstForThresholdSession: async () => undefined,
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
          rpcCall: { nearAccountId: 'alice.testnet' },
          deviceNumber: 1,
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
      clearAllCachedEd25519AuthSessions();
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

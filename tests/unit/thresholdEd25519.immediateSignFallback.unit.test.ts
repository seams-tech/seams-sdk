import { expect, test } from '@playwright/test';
import { signTransactionsWithActions } from '@/core/signingEngine/orchestration/near/transactionsFlow';
import {
  buildAndCacheEd25519AuthSession,
  clearAllCachedEd25519AuthSessions,
} from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import { ActionType } from '@/core/types/actions';
import { WorkerResponseType } from '@/core/types/signer-worker';

class MemorySessionStorage implements Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'> {
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
    (globalThis as { sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'> }).sessionStorage =
      sessionStorage;

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

    clearAllCachedEd25519AuthSessions();

    try {
      const nearAccountId = 'immediate-fallback.testnet';
      const sessionId = 'threshold-ed25519-session-1';
      const relayerUrl = 'https://relay.example.test';
      const relayerKeyId = 'ed25519:relayer-key-id';
      const rpId = 'example.localhost';

      await buildAndCacheEd25519AuthSession({
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

      // Simulate a fresh signing attempt after the in-memory warm cache and auth cache are gone,
      // while the persisted session record still exists.
      clearAllCachedEd25519AuthSessions();

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
      let dispenseCalls = 0;
      let workerThresholdSessionJwt = '';
      let workerCredentialJson = '';

      const signed = await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            getNearThresholdKeyMaterial: async () => ({
              nearAccountId,
              deviceNumber: 1,
              kind: 'threshold_ed25519_2p_v1' as const,
              publicKey: 'ed25519:threshold-public-key',
              recoveryPublicKey: 'ed25519:recovery-public-key',
              artifactKind: 'near-ed25519-option-b-v1' as const,
              relayerKeyId,
              keyVersion: 'option-b-v1',
              recoveryExportCapable: true as const,
              clientShareDerivation: 'prf_first_v1' as const,
              clientExportShareDerivation: 'prf_first_v1' as const,
              wrapKeySalt: 'wrap-key-salt-b64u',
              timestamp: Date.now(),
              participants: [
                { id: 1, role: 'client', shareDerivation: 'prf_first_v1' as const },
                {
                  id: 2,
                  role: 'relayer',
                  relayerUrl,
                  relayerKeyId,
                  verifyingShareB64u: 'relayer-verifying-share-b64u',
                  shareDerivation: 'derived_master_secret_v1' as const,
                },
              ],
            }),
          },
          nonceManager: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => rpId,
          },
          relayerUrl,
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm cache missing',
            }),
            dispensePrfFirstForThresholdSession: async () => {
              dispenseCalls += 1;
              return { ok: false as const, code: 'unexpected', message: 'should not dispense' };
            },
            clearPrfFirstForThresholdSession: async () => undefined,
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
      expect(dispenseCalls).toBe(0);
      expect(workerThresholdSessionJwt).toBe('persisted-threshold-jwt');
      expect(workerCredentialJson).toContain('cred-id');
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

import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import bs58 from 'bs58';
import { buildAndCacheEd25519AuthSession } from '@/core/signingEngine/threshold/session/ed25519AuthSession';
import {
  ensureThresholdEd25519HssClientBase,
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import { signTransactionsWithActions } from '@/core/signingEngine/orchestration/near/transactionsFlow';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionClientBase,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { ActionType, type TransactionInputWasm } from '@/core/types/actions';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';
import { deriveThresholdEd25519HssClientInputsWasm } from '@/core/signingEngine/signers/wasm/nearSignerWasm';
import {
  evaluateThresholdEd25519HssResultWasm,
  openThresholdEd25519HssClientOutputWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from '@/core/signingEngine/signers/wasm/nearSignerHssWasm';
import {
  finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration,
  prepareThresholdEd25519HssServerCeremonyWithRelayRegistration,
} from '@/core/TatchiPasskey/faucets/createAccountRelayServer';
import {
  deriveThresholdEd25519HssPublicKey,
  finalizeThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerCeremony,
} from '../../server/src/core/ThresholdService/ed25519HssWasm';
import { handle_signer_message } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';

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

const NEAR_ACCOUNT_ID = 'option-a-active.testnet';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'ed25519:relayer-key-id';
const RP_ID = 'example.localhost';
const THRESHOLD_SESSION_ID = 'threshold-ed25519-option-a-session';
const THRESHOLD_SESSION_JWT = 'header.payload.signature';
const CONTEXT = {
  orgId: 'org_option_a',
  nearAccountId: NEAR_ACCOUNT_ID,
  keyPurpose: 'near-ed25519-signing',
  keyVersion: 'root-v1',
  participantIds: [1, 2],
  derivationVersion: 1,
} as const;
const RUNTIME_SCOPE = {
  orgId: CONTEXT.orgId,
  environmentId: 'env_option_a',
} as const;
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const MASTER_SECRET_B64U = Buffer.alloc(32, 7).toString('base64url');
const NEAR_SIGNER_WASM_URL = new URL(
  '../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  import.meta.url,
);

function installMemorySessionStorage(): {
  restore: () => void;
  storage: MemorySessionStorage;
} {
  const original = (globalThis as { sessionStorage?: Storage }).sessionStorage;
  const storage = new MemorySessionStorage();
  (
    globalThis as { sessionStorage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem' | 'clear'> }
  ).sessionStorage = storage;
  return {
    storage,
    restore: () => {
      storage.clear();
      if (original) {
        (globalThis as { sessionStorage?: Storage }).sessionStorage = original;
      } else {
        delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
      }
    },
  };
}

function withoutSessionStorage<T>(fn: () => T): T {
  const original = (globalThis as { sessionStorage?: Storage }).sessionStorage;
  delete (globalThis as { sessionStorage?: Storage }).sessionStorage;
  try {
    return fn();
  } finally {
    if (original) {
      (globalThis as { sessionStorage?: Storage }).sessionStorage = original;
    }
  }
}

function seedThresholdEd25519Session(args?: { xClientBaseB64u?: string }): void {
  upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: NEAR_ACCOUNT_ID,
    rpId: RP_ID,
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: [...CONTEXT.participantIds],
    runtimeSnapshotScope: { ...RUNTIME_SCOPE },
    ...(String(args?.xClientBaseB64u || '').trim()
      ? { xClientBaseB64u: String(args?.xClientBaseB64u || '').trim() }
      : {}),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    thresholdSessionJwt: THRESHOLD_SESSION_JWT,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 10,
    source: 'test',
  });
}

function makeThresholdKeyMaterial(publicKey: string) {
  return {
    nearAccountId: NEAR_ACCOUNT_ID,
    deviceNumber: 1,
    kind: 'threshold_ed25519_v1' as const,
    publicKey,
    relayerKeyId: RELAYER_KEY_ID,
    keyVersion: CONTEXT.keyVersion,
    timestamp: Date.now(),
    participants: [
      { id: 1, role: 'client' },
      {
        id: 2,
        role: 'relayer',
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
      },
    ],
  };
}

async function maybeServeLocalNearSignerWasm(url: string): Promise<Response | null> {
  if (!url.startsWith('file://') || !url.endsWith('/wasm_signer_worker_bg.wasm')) {
    return null;
  }
  const bytes = await readFile(NEAR_SIGNER_WASM_URL);
  return new Response(bytes, {
    status: 200,
    headers: { 'Content-Type': 'application/wasm' },
  });
}

async function invokeNearSignerWorkerDirect(request: {
  sessionId?: string;
  type: number;
  payload?: Record<string, unknown>;
}): Promise<any> {
  return handle_signer_message({
    type: request.type,
    payload: {
      sessionId: String(request.sessionId || '').trim(),
      ...(request.payload || {}),
    },
  });
}

test.describe('threshold Ed25519 Option A active path', () => {
  test('preserves xClientBaseB64u when rebuilding the same auth session record', async () => {
    const { restore } = installMemorySessionStorage();
    const expectedXClientBaseB64u = Buffer.alloc(32, 29).toString('base64url');

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: expectedXClientBaseB64u });

    try {
      await buildAndCacheEd25519AuthSession({
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        runtimeSnapshotScope: { ...RUNTIME_SCOPE },
        participantIds: [...CONTEXT.participantIds],
        sessionId: THRESHOLD_SESSION_ID,
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 5,
        jwt: THRESHOLD_SESSION_JWT,
        source: 'test',
      });

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      expect(String(stored?.xClientBaseB64u || '')).toBe(expectedXClientBaseB64u);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('keeps threshold Ed25519 session state in memory when sessionStorage is unavailable', async () => {
    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const seeded = withoutSessionStorage(() =>
        upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: NEAR_ACCOUNT_ID,
          rpId: RP_ID,
          relayerUrl: RELAYER_URL,
          relayerKeyId: RELAYER_KEY_ID,
          participantIds: [...CONTEXT.participantIds],
          runtimeSnapshotScope: { ...RUNTIME_SCOPE },
          thresholdSessionKind: 'jwt',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          thresholdSessionJwt: THRESHOLD_SESSION_JWT,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 10,
          source: 'bootstrap',
        }),
      );

      expect(seeded).not.toBeNull();

      const loaded = withoutSessionStorage(() =>
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID),
      );
      expect(loaded?.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
      expect(loaded?.runtimeSnapshotScope?.orgId).toBe(RUNTIME_SCOPE.orgId);

      const persisted = withoutSessionStorage(() =>
        persistStoredThresholdEd25519SessionClientBase({
          thresholdSessionId: THRESHOLD_SESSION_ID,
          xClientBaseB64u: Buffer.alloc(32, 31).toString('base64url'),
        }),
      );
      expect(String(persisted?.xClientBaseB64u || '')).toBe(
        Buffer.alloc(32, 31).toString('base64url'),
      );
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('reconstructs and persists xClientBaseB64u through the real HSS ceremony', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    let serverOutputXRelayerBaseB64u = '';

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        const prepared = await prepareThresholdEd25519HssServerCeremony({
          context: body.context,
          masterSecretB64u: MASTER_SECRET_B64U,
          preparedSession: body.preparedSession,
          clientRequest: body.clientRequest,
        });
        return new Response(JSON.stringify({ ok: true, serverMessage: prepared.serverMessage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await finalizeThresholdEd25519HssServerCeremony({
          preparedSession: body.preparedSession,
          evaluationResult: body.evaluationResult,
        });
        serverOutputXRelayerBaseB64u = String(finalized.serverOutput.xRelayerBaseB64u || '').trim();
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
        ctx: {
          requestWorkerOperation: async ({ request }) =>
            await invokeNearSignerWorkerDirect(request),
        } as any,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        thresholdSessionJwt: THRESHOLD_SESSION_JWT,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        prfFirstB64u: PRF_FIRST_B64U,
      });

      expect(String(xClientBaseB64u || '')).not.toBe('');
      expect(serverOutputXRelayerBaseB64u).not.toBe('');

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      expect(String(stored?.xClientBaseB64u || '')).toBe(String(xClientBaseB64u || ''));

      const derived = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u: String(xClientBaseB64u || ''),
        xRelayerBaseB64u: serverOutputXRelayerBaseB64u,
      });
      expect(String(derived.publicKeyB64u || '')).not.toBe('');
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('forwards only xClientBaseB64u into the live signer worker payload', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session({ xClientBaseB64u: Buffer.alloc(32, 23).toString('base64url') });

    await buildAndCacheEd25519AuthSession({
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimeSnapshotScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'test',
    });

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

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
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    let capturedPayload: Record<string, any> | null = null;

    try {
      const result = await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            getNearThresholdKeyMaterial: async () =>
              makeThresholdKeyMaterial('ed25519:threshold-public-key'),
          },
          nonceManager: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm cache missing',
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
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            capturedPayload = request?.payload || null;
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
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID },
        deviceNumber: 1,
        sessionId: THRESHOLD_SESSION_ID,
      });

      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(1);

      const thresholdPayload = capturedPayload?.threshold || {};
      expect(String(thresholdPayload.xClientBaseB64u || '')).toBe(
        Buffer.alloc(32, 23).toString('base64url'),
      );
      expect(
        Object.prototype.hasOwnProperty.call(thresholdPayload, 'clientVerifyingShareB64u'),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(thresholdPayload, 'keyVersion')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(capturedPayload || {}, 'prfFirstB64u')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(capturedPayload || {}, 'wrapKeySalt')).toBe(
        false,
      );
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('prefers Option A seed export from the active warm threshold session', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const exportWorkerCalls: Array<Record<string, unknown>> = [];

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        const prepared = await prepareThresholdEd25519HssServerCeremony({
          context: body.context,
          masterSecretB64u: MASTER_SECRET_B64U,
          preparedSession: body.preparedSession,
          clientRequest: body.clientRequest,
        });
        return new Response(JSON.stringify({ ok: true, serverMessage: prepared.serverMessage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await finalizeThresholdEd25519HssServerCeremony({
          preparedSession: body.preparedSession,
          evaluationResult: body.evaluationResult,
        });
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const preparedSession = await prepareThresholdEd25519HssSessionWasm({
        context: {
          orgId: CONTEXT.orgId,
          nearAccountId: NEAR_ACCOUNT_ID,
          keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
          keyVersion: CONTEXT.keyVersion,
          participantIds: [...CONTEXT.participantIds],
          derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        },
      });
      const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
        sessionId: `${THRESHOLD_SESSION_ID}:option-a-export-test-inputs`,
        orgId: CONTEXT.orgId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: preparedSession.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        prfFirstB64u: PRF_FIRST_B64U,
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) =>
            await invokeNearSignerWorkerDirect(request),
        },
      });
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        preparedSession,
        clientInputs,
      });
      const prepared = await prepareThresholdEd25519HssServerCeremony({
        context: {
          orgId: CONTEXT.orgId,
          nearAccountId: NEAR_ACCOUNT_ID,
          keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
          keyVersion: CONTEXT.keyVersion,
          participantIds: [...CONTEXT.participantIds],
          derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        },
        masterSecretB64u: MASTER_SECRET_B64U,
        preparedSession,
        clientRequest,
      });
      const evaluationResult = await evaluateThresholdEd25519HssResultWasm({
        preparedSession,
        clientRequest,
        serverMessage: prepared.serverMessage,
      });
      const finalized = await finalizeThresholdEd25519HssServerCeremony({
        preparedSession,
        evaluationResult,
      });
      const clientOutput = await openThresholdEd25519HssClientOutputWasm({
        preparedSession,
        finalizedReport: finalized.finalizedReport,
      });
      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u: clientOutput.xClientBaseB64u,
        xRelayerBaseB64u: finalized.serverOutput.xRelayerBaseB64u,
      });
      const expectedPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
        orchestrationDeps: any;
        touchConfirm: any;
      };

      engine.orchestrationDeps = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            clientDB: {
              resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
              getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
            },
            getNearThresholdKeyMaterial: async () => makeThresholdKeyMaterial(expectedPublicKey),
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
            exportWorkerCalls.push(payload);
            return {
              ok: true,
              accountId: String(payload.nearAccountId || ''),
              exportedSchemes: ['ed25519'],
            };
          },
        },
        indexedDB: {
          clientDB: {
            resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
            getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
          },
          getNearThresholdKeyMaterial: async () => makeThresholdKeyMaterial(expectedPublicKey),
        },
        signingSessionStateDeps: {
          activeSigningSessionIds: new Map<string, string>(),
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: true as const,
              remainingUses: 5,
              expiresAtMs: Date.now() + 60_000,
            }),
          },
          createSessionId: (prefix: string) => `${prefix}-unused`,
          signingSessionDefaults: { ttlMs: 60_000, remainingUses: 5 },
          resolveCanonicalSigningSessionIdForKind: () => THRESHOLD_SESSION_ID,
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };

      engine.touchConfirm = {
        dispensePrfFirstForThresholdSession: async () => ({
          ok: true as const,
          prfFirstB64u: PRF_FIRST_B64U,
          remainingUses: 4,
          expiresAtMs: Date.now() + 60_000,
        }),
      };

      const result = await engine.exportKeypairWithUI(NEAR_ACCOUNT_ID as any, {
        chain: 'near',
        variant: 'drawer',
      });

      expect(result).toEqual({
        accountId: NEAR_ACCOUNT_ID,
        exportedSchemes: ['ed25519'],
      });
      expect(exportWorkerCalls).toHaveLength(1);
      expect(exportWorkerCalls[0]).toMatchObject({
        nearAccountId: NEAR_ACCOUNT_ID,
        deviceNumber: 1,
        chain: 'near',
        artifactKind: 'near-ed25519-seed-v1',
        expectedPublicKey,
        variant: 'drawer',
        theme: 'dark',
      });
      expect(String(exportWorkerCalls[0]?.seedB64u || '')).not.toBe('');
      expect(
        Object.prototype.hasOwnProperty.call(exportWorkerCalls[0] || {}, 'recoveryPublicKey'),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(exportWorkerCalls[0] || {}, 'recoveryExportCapable'),
      ).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(exportWorkerCalls[0] || {}, 'keyVersion')).toBe(
        false,
      );
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('fails closed for NEAR export when canonical Option A session prerequisites are missing', async () => {
    const { restore } = installMemorySessionStorage();

    clearAllStoredThresholdEd25519SessionRecords();

    try {
      const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
        orchestrationDeps: any;
        touchConfirm: any;
      };

      engine.orchestrationDeps = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            clientDB: {
              resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
              getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
            },
            getNearThresholdKeyMaterial: async () => ({
              ...makeThresholdKeyMaterial('ed25519:unused'),
              participants: [],
            }),
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async () => {
            throw new Error('legacy Option B export worker path should not be reached');
          },
        },
        indexedDB: {
          clientDB: {
            resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
            getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
          },
          getNearThresholdKeyMaterial: async () => null,
        },
        signingSessionStateDeps: {
          activeSigningSessionIds: new Map<string, string>(),
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'missing warm session',
            }),
          },
          createSessionId: (prefix: string) => `${prefix}-unused`,
          signingSessionDefaults: { ttlMs: 60_000, remainingUses: 5 },
          resolveCanonicalSigningSessionIdForKind: () => null,
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };

      engine.touchConfirm = {
        dispensePrfFirstForThresholdSession: async () => ({
          ok: false as const,
          code: 'not_found',
          message: 'missing warm PRF',
        }),
      };

      await expect(
        engine.exportKeypairWithUI(NEAR_ACCOUNT_ID as any, {
          chain: 'near',
          variant: 'drawer',
        }),
      ).rejects.toThrow('NEAR Ed25519 export now requires the canonical Option A HSS export path');
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('binds signing and export to the same canonical public key over the route/session flow', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const exportWorkerCalls: Array<Record<string, unknown>> = [];
    let thresholdPublicKey = 'ed25519:placeholder';
    let lastServerOutputB64u = '';
    let lastContextBinding = '';
    let capturedSigningPayload: Record<string, any> | null = null;

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    await buildAndCacheEd25519AuthSession({
      nearAccountId: NEAR_ACCOUNT_ID,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      relayerKeyId: RELAYER_KEY_ID,
      runtimeSnapshotScope: { ...RUNTIME_SCOPE },
      participantIds: [...CONTEXT.participantIds],
      sessionId: THRESHOLD_SESSION_ID,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      jwt: THRESHOLD_SESSION_JWT,
      source: 'test',
    });

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) return wasmResponse;
      if (url.endsWith('/threshold-ed25519/healthz')) {
        return new Response(JSON.stringify({ ok: true, configured: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;
      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        const prepared = await prepareThresholdEd25519HssServerCeremony({
          context: body.context,
          masterSecretB64u: MASTER_SECRET_B64U,
          preparedSession: body.preparedSession,
          clientRequest: body.clientRequest,
        });
        lastContextBinding = String(prepared.serverMessage.contextBindingB64u || '').trim();
        return new Response(JSON.stringify({ ok: true, serverMessage: prepared.serverMessage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        const finalized = await finalizeThresholdEd25519HssServerCeremony({
          preparedSession: body.preparedSession,
          evaluationResult: body.evaluationResult,
        });
        lastServerOutputB64u = String(finalized.serverOutput.xRelayerBaseB64u || '').trim();
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

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
        prf: { results: { first: PRF_FIRST_B64U, second: undefined } },
      },
    };

    try {
      await signTransactionsWithActions({
        ctx: {
          indexedDB: {
            getNearThresholdKeyMaterial: async () => makeThresholdKeyMaterial(thresholdPublicKey),
          },
          nonceManager: {
            initializeUser: () => undefined,
          },
          touchIdPrompt: {
            getRpId: () => RP_ID,
          },
          relayerUrl: RELAYER_URL,
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false as const,
              code: 'not_found',
              message: 'warm cache missing',
            }),
            clearPrfFirstForThresholdSession: async () => undefined,
            orchestrateSigningConfirmation: async () => ({
              intentDigest: 'intent-digest-b64u',
              transactionContext: {
                nearPublicKeyStr: thresholdPublicKey,
                nextNonce: '1',
                txBlockHeight: '1',
                txBlockHash: 'blockhash',
                accessKeyInfo: { nonce: 0 },
              },
              credential: dummyCredential,
            }),
          },
          requestWorkerOperation: async ({ request }: any) => {
            if (request?.type === WorkerRequestType.SignTransactionsWithActions) {
              capturedSigningPayload = request?.payload || null;
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
            }
            return await invokeNearSignerWorkerDirect(request);
          },
        } as any,
        transactions: [
          {
            receiverId: NEAR_ACCOUNT_ID,
            actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
          } as TransactionInputWasm,
        ],
        rpcCall: { nearAccountId: NEAR_ACCOUNT_ID },
        deviceNumber: 1,
        sessionId: THRESHOLD_SESSION_ID,
      });

      const stored =
        getStoredThresholdEd25519SessionRecordByThresholdSessionId(THRESHOLD_SESSION_ID);
      const xClientBaseB64u = String(stored?.xClientBaseB64u || '').trim();
      expect(xClientBaseB64u).not.toBe('');
      expect(lastServerOutputB64u).not.toBe('');
      expect(lastContextBinding).not.toBe('');
      expect(String(capturedSigningPayload?.threshold?.xClientBaseB64u || '')).toBe(
        xClientBaseB64u,
      );

      const derivedPublicKey = await deriveThresholdEd25519HssPublicKey({
        xClientBaseB64u,
        xRelayerBaseB64u: lastServerOutputB64u,
      });
      thresholdPublicKey = `ed25519:${bs58.encode(
        Buffer.from(String(derivedPublicKey.publicKeyB64u || ''), 'base64url'),
      )}`;

      const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
        orchestrationDeps: any;
        touchConfirm: any;
      };
      engine.orchestrationDeps = {
        privateKeyExportRecoveryDeps: {
          indexedDB: {
            clientDB: {
              resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
              getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
            },
            getNearThresholdKeyMaterial: async () => makeThresholdKeyMaterial(thresholdPublicKey),
          },
          relayerUrl: RELAYER_URL,
          getRpId: () => RP_ID,
          getTheme: () => 'dark',
          requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
            exportWorkerCalls.push(payload);
            return {
              ok: true,
              accountId: String(payload.nearAccountId || ''),
              exportedSchemes: ['ed25519'],
            };
          },
        },
        indexedDB: {
          clientDB: {
            resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
            getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 1 }),
          },
          getNearThresholdKeyMaterial: async () => makeThresholdKeyMaterial(thresholdPublicKey),
        },
        signingSessionStateDeps: {
          activeSigningSessionIds: new Map<string, string>(),
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: true as const,
              remainingUses: 5,
              expiresAtMs: Date.now() + 60_000,
            }),
          },
          createSessionId: (prefix: string) => `${prefix}-unused`,
          signingSessionDefaults: { ttlMs: 60_000, remainingUses: 5 },
          resolveCanonicalSigningSessionIdForKind: () => THRESHOLD_SESSION_ID,
        },
        thresholdSessionActivationDeps: {
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: any) =>
              await invokeNearSignerWorkerDirect(request),
          }),
        },
      };
      engine.touchConfirm = {
        dispensePrfFirstForThresholdSession: async () => ({
          ok: true as const,
          prfFirstB64u: PRF_FIRST_B64U,
          remainingUses: 4,
          expiresAtMs: Date.now() + 60_000,
        }),
      };

      const exportResult = await engine.exportKeypairWithUI(NEAR_ACCOUNT_ID as any, {
        chain: 'near',
        variant: 'drawer',
      });

      expect(exportResult).toEqual({
        accountId: NEAR_ACCOUNT_ID,
        exportedSchemes: ['ed25519'],
      });
      expect(exportWorkerCalls).toHaveLength(1);
      expect(exportWorkerCalls[0]).toMatchObject({
        nearAccountId: NEAR_ACCOUNT_ID,
        artifactKind: 'near-ed25519-seed-v1',
        expectedPublicKey: thresholdPublicKey,
      });
      expect(String(exportWorkerCalls[0]?.seedB64u || '')).not.toBe('');
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('keeps HSS route payloads input-segregated and free of raw cross-party secret material', async () => {
    const { restore } = installMemorySessionStorage();
    const originalFetch = globalThis.fetch;
    const prepareRequests: Array<Record<string, any>> = [];
    const finalizeRequests: Array<Record<string, any>> = [];
    const prepareResponses: Array<Record<string, any>> = [];
    const finalizeResponses: Array<Record<string, any>> = [];

    clearAllStoredThresholdEd25519SessionRecords();
    seedThresholdEd25519Session();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/threshold-ed25519/hss/prepare')) {
        prepareRequests.push(body);
        const prepared = await prepareThresholdEd25519HssServerCeremony({
          context: body.context,
          masterSecretB64u: MASTER_SECRET_B64U,
          preparedSession: body.preparedSession,
          clientRequest: body.clientRequest,
        });
        const responseBody = { ok: true, serverMessage: prepared.serverMessage };
        prepareResponses.push(responseBody);
        return new Response(JSON.stringify(responseBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/threshold-ed25519/hss/finalize')) {
        finalizeRequests.push(body);
        const finalized = await finalizeThresholdEd25519HssServerCeremony({
          preparedSession: body.preparedSession,
          evaluationResult: body.evaluationResult,
        });
        const responseBody = {
          ok: true,
          finalizedReport: finalized.finalizedReport,
        };
        finalizeResponses.push(responseBody);
        return new Response(JSON.stringify(responseBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
        ctx: {
          requestWorkerOperation: async ({ request }) =>
            await invokeNearSignerWorkerDirect(request),
        } as any,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        thresholdSessionJwt: THRESHOLD_SESSION_JWT,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        prfFirstB64u: PRF_FIRST_B64U,
      });

      expect(String(xClientBaseB64u || '')).not.toBe('');
      expect(prepareRequests).toHaveLength(1);
      expect(finalizeRequests).toHaveLength(1);
      expect(prepareResponses).toHaveLength(1);
      expect(finalizeResponses).toHaveLength(1);

      const prepareRequestJson = JSON.stringify(prepareRequests[0]);
      const finalizeRequestJson = JSON.stringify(finalizeRequests[0]);
      const prepareResponseJson = JSON.stringify(prepareResponses[0]);
      const finalizeResponseJson = JSON.stringify(finalizeResponses[0]);

      expect(prepareRequests[0]).toHaveProperty('context');
      expect(prepareRequests[0]).toHaveProperty('preparedSession');
      expect(prepareRequests[0]).toHaveProperty('clientRequest');
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'clientInputs')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'prfFirstB64u')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareRequests[0], 'xClientBaseB64u')).toBe(
        false,
      );
      expect(prepareRequestJson.includes(PRF_FIRST_B64U)).toBe(false);
      expect(prepareRequestJson.includes(MASTER_SECRET_B64U)).toBe(false);

      expect(prepareResponses[0]).toHaveProperty('serverMessage');
      expect(Object.prototype.hasOwnProperty.call(prepareResponses[0], 'serverOutput')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(prepareResponses[0], 'serverInputs')).toBe(false);
      expect(prepareResponseJson.includes(MASTER_SECRET_B64U)).toBe(false);

      expect(finalizeRequests[0]).toHaveProperty('preparedSession');
      expect(finalizeRequests[0]).toHaveProperty('evaluationResult');
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'prfFirstB64u')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'xClientBaseB64u')).toBe(
        false,
      );
      expect(Object.prototype.hasOwnProperty.call(finalizeRequests[0], 'seedB64u')).toBe(false);
      expect(finalizeRequestJson.includes(PRF_FIRST_B64U)).toBe(false);
      expect(finalizeRequestJson.includes(MASTER_SECRET_B64U)).toBe(false);

      expect(finalizeResponses[0]).toHaveProperty('finalizedReport');
      expect(Object.prototype.hasOwnProperty.call(finalizeResponses[0], 'serverOutput')).toBe(
        false,
      );
      expect(finalizeResponseJson.includes('xRelayerBaseB64u')).toBe(false);
      expect(finalizeResponseJson.includes(MASTER_SECRET_B64U)).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllStoredThresholdEd25519SessionRecords();
      restore();
    }
  });

  test('uses the sessionless registration HSS routes with per-request bootstrap grants', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapGrantBodies: Array<Record<string, any>> = [];
    const prepareBodies: Array<Record<string, any>> = [];
    const finalizeBodies: Array<Record<string, any>> = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const wasmResponse = await maybeServeLocalNearSignerWasm(url);
      if (wasmResponse) {
        return wasmResponse;
      }
      const body = JSON.parse(String(init?.body || '{}')) as Record<string, any>;

      if (url.endsWith('/v1/registration/bootstrap-grants')) {
        bootstrapGrantBodies.push(body);
        return new Response(
          JSON.stringify({
            ok: true,
            grant: {
              token: `bootstrap-token-${bootstrapGrantBodies.length}`,
              expiresAt: new Date(Date.now() + 60_000).toISOString(),
              orgId: CONTEXT.orgId,
              projectId: 'project_option_a',
              environmentId: RUNTIME_SCOPE.environmentId,
              origin: 'https://example.localhost',
              mode: 'free',
            },
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      if (url.endsWith('/registration/threshold-ed25519/hss/prepare')) {
        prepareBodies.push(body);
        expect(
          String(init?.headers && (init.headers as Record<string, string>).Authorization),
        ).toBe('Bearer bootstrap-token-1');
        const prepared = await prepareThresholdEd25519HssServerCeremony({
          context: body.context,
          masterSecretB64u: MASTER_SECRET_B64U,
          preparedSession: body.preparedSession,
          clientRequest: body.clientRequest,
        });
        return new Response(JSON.stringify({ ok: true, serverMessage: prepared.serverMessage }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }

      if (url.endsWith('/registration/threshold-ed25519/hss/finalize')) {
        finalizeBodies.push(body);
        expect(
          String(init?.headers && (init.headers as Record<string, string>).Authorization),
        ).toBe('Bearer bootstrap-token-2');
        const finalized = await finalizeThresholdEd25519HssServerCeremony({
          preparedSession: body.preparedSession,
          evaluationResult: body.evaluationResult,
        });
        return new Response(
          JSON.stringify({
            ok: true,
            finalizedReport: finalized.finalizedReport,
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }

      throw new Error(`unexpected fetch in test: ${url}`);
    }) as typeof fetch;

    try {
      const preparedSession = await prepareThresholdEd25519HssSessionWasm({
        context: {
          orgId: CONTEXT.orgId,
          nearAccountId: NEAR_ACCOUNT_ID,
          keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
          keyVersion: CONTEXT.keyVersion,
          participantIds: [...CONTEXT.participantIds],
          derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        },
      });
      const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
        sessionId: `${THRESHOLD_SESSION_ID}:registration-inputs`,
        orgId: CONTEXT.orgId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: preparedSession.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
        prfFirstB64u: PRF_FIRST_B64U,
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) =>
            await invokeNearSignerWorkerDirect(request),
        },
      });
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        preparedSession,
        clientInputs,
      });
      const hssContext = {
        orgId: CONTEXT.orgId,
        nearAccountId: NEAR_ACCOUNT_ID,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: CONTEXT.keyVersion,
        participantIds: [...CONTEXT.participantIds],
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      };

      const registrationContext = {
        configs: {
          network: {
            relayer: {
              url: RELAYER_URL,
            },
          },
          registration: {
            mode: 'managed',
            environmentId: RUNTIME_SCOPE.environmentId,
            publishableKey: 'pk_test_option_a',
          },
        },
      } as any;

      const serverMessage = await prepareThresholdEd25519HssServerCeremonyWithRelayRegistration({
        context: registrationContext,
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        hssContext,
        preparedSession,
        clientRequest,
      });
      const evaluationResult = await evaluateThresholdEd25519HssResultWasm({
        preparedSession,
        clientRequest,
        serverMessage,
      });
      const finalized = await finalizeThresholdEd25519HssServerCeremonyWithRelayRegistration({
        context: registrationContext,
        nearAccountId: NEAR_ACCOUNT_ID,
        rpId: RP_ID,
        hssContext,
        preparedSession,
        evaluationResult,
      });

      expect(String(serverMessage.contextBindingB64u || '')).toBe(
        String(preparedSession.contextBindingB64u || ''),
      );
      expect(String(finalized.finalizedReport.contextBindingB64u || '')).toBe(
        String(preparedSession.contextBindingB64u || ''),
      );
      expect(bootstrapGrantBodies).toHaveLength(2);
      expect(bootstrapGrantBodies.map((entry) => entry.path)).toEqual([
        '/registration/threshold-ed25519/hss/prepare',
        '/registration/threshold-ed25519/hss/finalize',
      ]);
      expect(prepareBodies).toHaveLength(1);
      expect(finalizeBodies).toHaveLength(1);
      expect(String(prepareBodies[0]?.new_account_id || '')).toBe(NEAR_ACCOUNT_ID);
      expect(String(prepareBodies[0]?.rp_id || '')).toBe(RP_ID);
      expect(String(finalizeBodies[0]?.new_account_id || '')).toBe(NEAR_ACCOUNT_ID);
      expect(String(finalizeBodies[0]?.rp_id || '')).toBe(RP_ID);
      expect(JSON.stringify(prepareBodies[0]).includes(PRF_FIRST_B64U)).toBe(false);
      expect(JSON.stringify(prepareBodies[0]).includes(MASTER_SECRET_B64U)).toBe(false);
      expect(JSON.stringify(finalizeBodies[0]).includes(PRF_FIRST_B64U)).toBe(false);
      expect(JSON.stringify(finalizeBodies[0]).includes(MASTER_SECRET_B64U)).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

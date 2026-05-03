import { expect, test } from '@playwright/test';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { persistLinkDeviceThresholdEcdsaBootstrap } from '@/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/orchestration/thresholdActivation';
import type { ThresholdEcdsaSessionStoreSource } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';

const ACCOUNT_ID = 'alice.testnet';
const RELAYER_URL = 'https://relay.example.test';
const RP_ID = 'wallet.example.test';
const PARTICIPANT_IDS = [1, 2];
const ETHEREUM_ADDRESS = `0x${'aa'.repeat(20)}`;
const CANONICAL_PUBLIC_KEY_HEX = `0x02${'11'.repeat(32)}`;
const PRIVATE_KEY_HEX = `0x${'22'.repeat(32)}`;
const PRF_FIRST_B64U = Buffer.alloc(32, 7).toString('base64url');

function makeUnsignedJwt(payload: Record<string, unknown>): string {
  const encode = (value: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

function makeThresholdEcdsaSessionJwt(sessionId: string): string {
  return makeUnsignedJwt({
    kind: 'threshold_ecdsa_session_v1',
    sub: ACCOUNT_ID,
    walletId: ACCOUNT_ID,
    sessionId,
    exp: 4_102_444_800,
  });
}

type CapturedRelayRequest = {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
};

type SessionStorageMock = {
  getItem: (key: string) => string | null;
  setItem: (key: string, value: string) => void;
  removeItem: (key: string) => void;
  clear: () => void;
};

function ensureSessionStorage(): SessionStorageMock {
  const globalObj = globalThis as { sessionStorage?: SessionStorageMock };
  if (globalObj.sessionStorage) return globalObj.sessionStorage;

  const store = new Map<string, string>();
  const sessionStorage: SessionStorageMock = {
    getItem: (key) => (store.has(key) ? String(store.get(key)) : null),
    setItem: (key, value) => {
      store.set(String(key), String(value));
    },
    removeItem: (key) => {
      store.delete(String(key));
    },
    clear: () => {
      store.clear();
    },
  };
  globalObj.sessionStorage = sessionStorage;
  return sessionStorage;
}

function createBootstrapResult(args?: {
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  sessionJwt?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const ecdsaThresholdKeyId = String(args?.ecdsaThresholdKeyId || 'ehss-key-1').trim();
  const sessionId = String(args?.sessionId || 'ecdsa-session-1').trim();
  const sessionJwt = String(args?.sessionJwt || makeThresholdEcdsaSessionJwt(sessionId)).trim();
  const walletSigningSessionId = `wss-${sessionId}`;

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: ACCOUNT_ID,
      relayerUrl: RELAYER_URL,
      ecdsaThresholdKeyId,
      signingRootId: 'proj_local:dev',
      backendBinding: {
        relayerKeyId: 'rk-1',
        clientVerifyingShareB64u: 'AQ',
      },
      participantIds: [...PARTICIPANT_IDS],
      thresholdEcdsaPublicKeyB64u: 'group-public-key-b64u',
      ethereumAddress: ETHEREUM_ADDRESS,
      relayerVerifyingShareB64u: 'relayer-share-b64u',
      thresholdSessionKind: 'jwt',
      thresholdSessionId: sessionId,
      thresholdSessionJwt: sessionJwt,
      walletSigningSessionId,
    },
    keygen: {
      ok: true,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u: 'AQ',
      relayerKeyId: 'rk-1',
      thresholdEcdsaPublicKeyB64u: 'group-public-key-b64u',
      ethereumAddress: ETHEREUM_ADDRESS,
      relayerVerifyingShareB64u: 'relayer-share-b64u',
      participantIds: [...PARTICIPANT_IDS],
    },
    session: {
      ok: true,
      sessionId,
      walletSigningSessionId,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      jwt: sessionJwt,
      clientVerifyingShareB64u: 'AQ',
    },
  };
}

function createExportTestEngine(args?: {
  accountAuthMethod?: 'passkey' | 'email_otp';
}) {
  const exportWorkerCalls: Array<Record<string, unknown>> = [];
  const userConfirmationCalls: Array<Record<string, unknown>> = [];
  const engine: any = Object.create(SigningEngine.prototype);
  const accountAuthMethod = args?.accountAuthMethod || 'passkey';

  ensureSessionStorage().clear();
  engine.seamsPasskeyConfigs = {
    network: {
      relayer: {
        url: RELAYER_URL,
      },
    },
    signing: {
      sessionSeal: {
        keyVersion: 'kek-s-export-test',
        shamirPrimeB64u: 'AQAB',
      },
    },
  };
  engine.theme = 'dark';
  engine.thresholdEcdsaBootstrapQueueByAccount = new Map();
  engine.thresholdEcdsaSessionByLane = new Map();
  engine.thresholdEcdsaExportArtifactByLane = new Map();
  engine.clearAllThresholdEcdsaSessionRecords();
  engine.touchIdPrompt = {
    getRpId: () => RP_ID,
  };
  engine.touchConfirm = {
    getWarmSessionStatus: async () => {
      throw new Error('warm-session status should not be consulted during export');
    },
    claimWarmSessionMaterial: async () => {
      throw new Error('warm-session claim should not be consumed during export');
    },
    requestUserConfirmation: async (request: Record<string, any>) => {
      userConfirmationCalls.push(request);
      if (request.type === 'decryptPrivateKeyWithPrf') {
        return {
          requestId: String(request.requestId || ''),
          confirmed: true,
          credential: {
            id: 'cred-id',
            type: 'public-key',
            rawId: 'cred-rawid-b64u',
            authenticatorAttachment: 'platform',
            response: {
              clientDataJSON: 'client-data-json-b64u',
              authenticatorData: 'authenticator-data-b64u',
              signature: 'signature-b64u',
              userHandle: '',
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: PRF_FIRST_B64U,
                  second: Buffer.alloc(32, 9).toString('base64url'),
                },
              },
            },
          },
        };
      }
      return {
        requestId: String(request.requestId || ''),
        confirmed: true,
      };
    },
  };
  engine.orchestrationDeps = {
    indexedDB: {
      clientDB: {
        resolveProfileAccountContext: async () => ({
          profileId: 'profile-1',
          accountRef: { chainIdKey: 'near:testnet', accountAddress: ACCOUNT_ID },
        }),
        getProfile: async () => ({
          profileId: 'profile-1',
          defaultSignerSlot: 5,
        }),
        listAccountSigners: async () => [
          {
            profileId: 'profile-1',
            signerSlot: 5,
            signerAuthMethod: accountAuthMethod,
            status: 'active',
          },
        ],
        getLastProfileState: async () => ({
          profileId: 'profile-1',
          activeSignerSlot: 5,
        }),
      },
    },
    privateKeyExportRecoveryDeps: {
      indexedDB: {
        clientDB: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: ACCOUNT_ID },
          }),
          getLastProfileState: async () => ({
            profileId: 'profile-1',
            activeSignerSlot: 5,
          }),
        },
      },
      relayerUrl: RELAYER_URL,
      getRpId: () => RP_ID,
      getTheme: () => 'dark',
      requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
        exportWorkerCalls.push(payload);
        return {
          ok: true,
          accountId: String(payload.nearAccountId || ''),
          exportedSchemes: ['secp256k1'],
        };
      },
    },
    thresholdSessionActivationDeps: {
      getSignerWorkerContext: () => ({
        requestWorkerOperation: async ({ request }: any) => {
          switch (request?.type) {
            case WorkerRequestType.PrepareThresholdEcdsaHssSession:
              expect(request?.payload).toMatchObject({
                nearAccountId: ACCOUNT_ID,
                keyPurpose: 'evm-signing',
                keyVersion: 'v1',
              });
              return {
                type: WorkerResponseType.PrepareThresholdEcdsaHssSessionSuccess,
                payload: {
                  nearAccountId: ACCOUNT_ID,
                  keyPurpose: 'evm-signing',
                  keyVersion: 'v1',
                  contextBindingB64u: 'context-binding-b64u',
                  evaluatorDriverStateB64u: 'evaluator-driver-state-b64u',
                },
              };
            case WorkerRequestType.PrepareThresholdEcdsaHssClientRequest:
              return {
                type: WorkerResponseType.PrepareThresholdEcdsaHssClientRequestSuccess,
                payload: {
                  clientEvalRequestB64u: 'client-eval-request-b64u',
                },
              };
            case WorkerRequestType.FinalizeThresholdEcdsaHssClientRequest:
              return {
                type: WorkerResponseType.FinalizeThresholdEcdsaHssClientRequestSuccess,
                payload: {
                  clientEvalFinalizeB64u: 'client-eval-finalize-b64u',
                },
              };
            default:
              throw new Error(`unexpected signer worker request in test: ${String(request?.type)}`);
          }
        },
      }),
    },
  };

  return { engine, exportWorkerCalls, userConfirmationCalls };
}

async function encodeHiddenEvalServerResponseMessage(args: {
  ceremonyId: string;
  requestMessageB64u: string;
  serverEvalResponseB64u: string;
}): Promise<string> {
  return base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        v: 1,
        kind: 'threshold_ecdsa_hss_hidden_eval_server_response_v1',
        ceremonyId: args.ceremonyId,
        requestDigestB64u: base64UrlEncode(await sha256BytesUtf8(args.requestMessageB64u)),
        serverEvalResponseB64u: args.serverEvalResponseB64u,
      }),
    ),
  );
}

function installExplicitExportRelayStub(args?: {
  expectedEcdsaThresholdKeyId?: string;
  expectedJwt?: string;
}) {
  const requests: CapturedRelayRequest[] = [];
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
    const headers = new Headers(init?.headers);
    const capturedHeaders: Record<string, string> = {};
    headers.forEach((value, key) => {
      capturedHeaders[key] = value;
    });
    requests.push({ url, headers: capturedHeaders, body });

    if (url.endsWith('/threshold-ecdsa/hss/prepare')) {
      return new Response(
        JSON.stringify({
          ok: true,
          ceremonyId: 'ceremony-1',
          preparedServerSessionB64u: 'prepared-server-session-b64u',
          serverAssistInitB64u: 'server-assist-init-b64u',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    if (url.endsWith('/threshold-ecdsa/hss/respond')) {
      const ceremonyId = String(body.ceremonyId || '').trim();
      const requestMessageB64u = String(body.requestMessageB64u || '').trim();
      return new Response(
        JSON.stringify({
          ok: true,
          responseMessageB64u: await encodeHiddenEvalServerResponseMessage({
            ceremonyId,
            requestMessageB64u,
            serverEvalResponseB64u: 'server-eval-response-b64u',
          }),
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    if (url.endsWith('/threshold-ecdsa/hss/finalize')) {
      return new Response(
        JSON.stringify({
          ok: true,
          canonicalPublicKeyHex: CANONICAL_PUBLIC_KEY_HEX,
          privateKeyHex: PRIVATE_KEY_HEX,
          canonicalEthereumAddress: ETHEREUM_ADDRESS,
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    }

    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;

  return {
    requests,
    restore() {
      globalThis.fetch = originalFetch;
    },
    expectCapturedPrepare() {
      const prepare = requests.find((entry) => entry.url.endsWith('/threshold-ecdsa/hss/prepare'));
      expect(prepare).toBeDefined();
      expect(prepare?.body?.operation).toBe('explicit_key_export');
      expect(String(prepare?.body?.userId || '')).toBe(ACCOUNT_ID);
      expect(String(prepare?.body?.rpId || '')).toBe(RP_ID);
      if (args?.expectedEcdsaThresholdKeyId) {
        expect(String(prepare?.body?.ecdsaThresholdKeyId || '')).toBe(
          args.expectedEcdsaThresholdKeyId,
        );
      }
      if (args?.expectedJwt) {
        expect(String(prepare?.headers?.authorization || '')).toBe(`Bearer ${args.expectedJwt}`);
      }
    },
  };
}

async function expectOneKeyEcdsaExportFromEngine(args: {
  engine: SigningEngine;
  expectedEcdsaThresholdKeyId: string;
  expectedJwt: string;
  exportWorkerCalls: Array<Record<string, unknown>>;
  userConfirmationCalls: Array<Record<string, unknown>>;
}) {
  const relay = installExplicitExportRelayStub({
    expectedEcdsaThresholdKeyId: args.expectedEcdsaThresholdKeyId,
    expectedJwt: args.expectedJwt,
  });
  try {
    const result = await args.engine.exportKeypairWithUI(ACCOUNT_ID as any, {
      chain: 'evm',
      variant: 'modal',
    });

    expect(result).toEqual({
      accountId: ACCOUNT_ID,
      exportedSchemes: ['secp256k1'],
    });
    relay.expectCapturedPrepare();
    expect(args.exportWorkerCalls).toHaveLength(0);
    expect(args.userConfirmationCalls.map((entry) => entry.type)).toEqual([
      'decryptPrivateKeyWithPrf',
      'showSecurePrivateKeyUi',
    ]);
    expect(args.userConfirmationCalls[0]).toMatchObject({
      summary: {
        accountId: ACCOUNT_ID,
      },
    });
    expect(args.userConfirmationCalls[1]).toMatchObject({
      payload: {
        nearAccountId: ACCOUNT_ID,
        publicKey: CANONICAL_PUBLIC_KEY_HEX,
        variant: 'modal',
        theme: 'dark',
        keys: [
          {
            scheme: 'secp256k1',
            publicKey: CANONICAL_PUBLIC_KEY_HEX,
            privateKey: PRIVATE_KEY_HEX,
            address: ETHEREUM_ADDRESS,
          },
        ],
      },
      summary: {
        accountId: ACCOUNT_ID,
        publicKey: CANONICAL_PUBLIC_KEY_HEX,
      },
    });
  } finally {
    relay.restore();
  }
}

test.describe('threshold ECDSA one-key source-flow export', () => {
  test('exports through staged explicit export for registration-sourced one-key sessions', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine();
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-registration-1',
      sessionId: 'ecdsa-registration-session-1',
      sessionJwt: makeThresholdEcdsaSessionJwt('ecdsa-registration-session-1'),
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'registration',
    });

    const record = engine.getThresholdEcdsaSessionRecordForLookup({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      source: 'registration',
    });
    expect(record.source).toBe('registration');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-registration-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-registration-1',
      expectedJwt: makeThresholdEcdsaSessionJwt('ecdsa-registration-session-1'),
      exportWorkerCalls,
      userConfirmationCalls,
    });
  });

  test('exports through staged explicit export for login-sourced one-key sessions', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine();
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-login-1',
      sessionId: 'ecdsa-login-session-1',
      sessionJwt: makeThresholdEcdsaSessionJwt('ecdsa-login-session-1'),
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'login',
    });

    const record = engine.getThresholdEcdsaSessionRecordForLookup({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      source: 'login',
    });
    expect(record.source).toBe('login');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-login-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-login-1',
      expectedJwt: makeThresholdEcdsaSessionJwt('ecdsa-login-session-1'),
      exportWorkerCalls,
      userConfirmationCalls,
    });
  });

  test('exports through staged explicit export for link-device manual-bootstrap one-key sessions', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine();

    await persistLinkDeviceThresholdEcdsaBootstrap({
      indexedDB: {
        clientDB: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: ACCOUNT_ID },
          }),
        },
        stageAccountSigner: async () => undefined,
        upsertAccountSigner: async () => undefined,
      } as any,
      signingEngine: {
        upsertThresholdEcdsaSessionFromBootstrap: (args) =>
          engine.upsertThresholdEcdsaSessionFromBootstrap(args),
        persistThresholdEcdsaBootstrapChainAccount: async () => undefined,
      },
      nearAccountId: ACCOUNT_ID,
      relayerUrl: RELAYER_URL,
      signerSlot: 2,
      rpId: RP_ID,
      credentialIdB64u: 'cred-b64u',
      thresholdEcdsa: {
        ecdsaThresholdKeyId: 'ehss-link-device-1',
        signingRootId: 'proj_local:dev',
        clientVerifyingShareB64u: 'AQ',
        clientAdditiveShare32B64u: 'Ag',
        relayerKeyId: 'rk-1',
        thresholdEcdsaPublicKeyB64u: 'group-public-key-b64u',
        ethereumAddress: ETHEREUM_ADDRESS,
        relayerVerifyingShareB64u: 'relayer-share-b64u',
        participantIds: [...PARTICIPANT_IDS],
        session: {
          sessionKind: 'jwt',
          sessionId: 'ecdsa-link-device-session-1',
          walletSigningSessionId: 'wss-ecdsa-link-device-session-1',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [...PARTICIPANT_IDS],
          remainingUses: 5,
          jwt: makeThresholdEcdsaSessionJwt('ecdsa-link-device-session-1'),
        },
      },
      linkedAccounts: [
        {
          chainIdKey: 'evm:11155111',
          chain: 'evm',
          chainId: 11155111,
          accountAddress: ETHEREUM_ADDRESS,
          accountModel: 'erc4337',
          counterfactualAddress: ETHEREUM_ADDRESS,
        },
      ],
    });

    const record = engine.getThresholdEcdsaSessionRecordForLookup({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      source: 'manual-bootstrap',
    });
    expect(record.source).toBe('manual-bootstrap');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-link-device-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-link-device-1',
      expectedJwt: makeThresholdEcdsaSessionJwt('ecdsa-link-device-session-1'),
      exportWorkerCalls,
      userConfirmationCalls,
    });
  });

  test('exports without consulting warm-session claim state or reconnecting the ECDSA session', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine();
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-stable-1',
      sessionId: 'ecdsa-stable-session-1',
      sessionJwt: makeThresholdEcdsaSessionJwt('ecdsa-stable-session-1'),
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'login',
    });
    (engine as any).provisionThresholdEcdsaSession = async () => {
      throw new Error('ECDSA export should not reconnect through session provisioning');
    };

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-stable-1',
      expectedJwt: makeThresholdEcdsaSessionJwt('ecdsa-stable-session-1'),
      exportWorkerCalls,
      userConfirmationCalls,
    });
    expect(exportWorkerCalls).toHaveLength(0);
  });

  test('fails ECDSA export when no exact export lane exists', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine();

    await expect(
      engine.exportKeypairWithUI(ACCOUNT_ID as any, {
        chain: 'evm',
        variant: 'modal',
      }),
    ).rejects.toThrow('[SigningEngine][ecdsa-export] exact lane selection failed: no_candidate');
    expect(exportWorkerCalls).toHaveLength(0);
    expect(userConfirmationCalls).toHaveLength(0);
  });

  test('rejects passkey-only ECDSA export when account metadata selects Email OTP', async () => {
    const { engine, exportWorkerCalls, userConfirmationCalls } = createExportTestEngine({
      accountAuthMethod: 'email_otp',
    });
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-passkey-runtime-1',
      sessionId: 'ecdsa-passkey-runtime-session-1',
      sessionJwt: makeThresholdEcdsaSessionJwt('ecdsa-passkey-runtime-session-1'),
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'login',
    });

    await expect(
      engine.exportKeypairWithUI(ACCOUNT_ID as any, {
        chain: 'evm',
        variant: 'modal',
      }),
    ).rejects.toThrow('[SigningEngine][ecdsa-export] exact lane selection failed: no_candidate');
    expect(exportWorkerCalls).toHaveLength(0);
    expect(userConfirmationCalls).toHaveLength(0);
  });
});

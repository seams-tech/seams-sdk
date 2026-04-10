import { expect, test } from '@playwright/test';
import { SigningEngine } from '@/core/signingEngine/SigningEngine';
import { persistLinkDeviceThresholdEcdsaBootstrap } from '@/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa';
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

type CapturedRelayRequest = {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
};

function createBootstrapResult(args?: {
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  sessionJwt?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const ecdsaThresholdKeyId = String(args?.ecdsaThresholdKeyId || 'ehss-key-1').trim();
  const sessionId = String(args?.sessionId || 'ecdsa-session-1').trim();
  const sessionJwt = String(args?.sessionJwt || 'jwt:ecdsa-session-1').trim();

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: ACCOUNT_ID,
      relayerUrl: RELAYER_URL,
      ecdsaThresholdKeyId,
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
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 5,
      jwt: sessionJwt,
      clientVerifyingShareB64u: 'AQ',
    },
  };
}

function createExportTestEngine() {
  const exportWorkerCalls: Array<Record<string, unknown>> = [];
  const engine = Object.create(SigningEngine.prototype) as SigningEngine & {
    orchestrationDeps: Record<string, unknown>;
    touchConfirm: Record<string, unknown>;
    touchIdPrompt: Record<string, unknown>;
    thresholdEcdsaSessionByLane: Map<string, unknown>;
    thresholdEcdsaExportArtifactByLane: Map<string, unknown>;
  };

  engine.thresholdEcdsaSessionByLane = new Map();
  engine.thresholdEcdsaExportArtifactByLane = new Map();
  engine.touchIdPrompt = {
    getRpId: () => RP_ID,
  };
  engine.touchConfirm = {
    dispensePrfFirstForThresholdSession: async (args: { sessionId: string }) => ({
      ok: true as const,
      prfFirstB64u: PRF_FIRST_B64U,
      remainingUses: 4,
      expiresAtMs: Date.now() + 60_000,
      sessionId: args.sessionId,
    }),
  };
  engine.orchestrationDeps = {
    privateKeyExportRecoveryDeps: {
      indexedDB: {
        clientDB: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: ACCOUNT_ID },
          }),
          getLastProfileState: async () => ({
            profileId: 'profile-1',
            deviceNumber: 5,
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
              return {
                type: WorkerResponseType.PrepareThresholdEcdsaHssSessionSuccess,
                payload: {
                  nearAccountId: ACCOUNT_ID,
                  keyPurpose: 'threshold-ecdsa',
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

  return { engine, exportWorkerCalls };
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
    expect(args.exportWorkerCalls).toHaveLength(1);
    expect(args.exportWorkerCalls[0]).toMatchObject({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      artifactKind: 'ecdsa-hss-secp256k1-key-v1',
      publicKeyHex: CANONICAL_PUBLIC_KEY_HEX,
      privateKeyHex: PRIVATE_KEY_HEX,
      ethereumAddress: ETHEREUM_ADDRESS,
      variant: 'modal',
      theme: 'dark',
    });
  } finally {
    relay.restore();
  }
}

test.describe('threshold ECDSA one-key source-flow export', () => {
  test('exports through staged explicit export for registration-sourced one-key sessions', async () => {
    const { engine, exportWorkerCalls } = createExportTestEngine();
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-registration-1',
      sessionId: 'ecdsa-registration-session-1',
      sessionJwt: 'jwt:ecdsa-registration-1',
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'registration',
    });

    const record = engine.getThresholdEcdsaSessionRecordForSigning({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
    });
    expect(record.source).toBe('registration');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-registration-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-registration-1',
      expectedJwt: 'jwt:ecdsa-registration-1',
      exportWorkerCalls,
    });
  });

  test('exports through staged explicit export for login-sourced one-key sessions', async () => {
    const { engine, exportWorkerCalls } = createExportTestEngine();
    const bootstrap = createBootstrapResult({
      ecdsaThresholdKeyId: 'ehss-login-1',
      sessionId: 'ecdsa-login-session-1',
      sessionJwt: 'jwt:ecdsa-login-1',
    });

    engine.upsertThresholdEcdsaSessionFromBootstrap({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
      bootstrap,
      source: 'login',
    });

    const record = engine.getThresholdEcdsaSessionRecordForSigning({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
    });
    expect(record.source).toBe('login');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-login-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-login-1',
      expectedJwt: 'jwt:ecdsa-login-1',
      exportWorkerCalls,
    });
  });

  test('exports through staged explicit export for link-device manual-bootstrap one-key sessions', async () => {
    const { engine, exportWorkerCalls } = createExportTestEngine();

    await persistLinkDeviceThresholdEcdsaBootstrap({
      indexedDB: {
        clientDB: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: ACCOUNT_ID },
          }),
        },
        upsertAccountSigner: async () => undefined,
      } as any,
      signingEngine: {
        upsertThresholdEcdsaSessionFromBootstrap: (args) =>
          engine.upsertThresholdEcdsaSessionFromBootstrap(args),
        persistThresholdEcdsaBootstrapChainAccount: async () => undefined,
      },
      nearAccountId: ACCOUNT_ID,
      relayerUrl: RELAYER_URL,
      deviceNumber: 2,
      rpId: RP_ID,
      credentialIdB64u: 'cred-b64u',
      thresholdEcdsa: {
        ecdsaThresholdKeyId: 'ehss-link-device-1',
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
          expiresAtMs: Date.now() + 60_000,
          participantIds: [...PARTICIPANT_IDS],
          remainingUses: 5,
          jwt: 'jwt:ecdsa-link-device-1',
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

    const record = engine.getThresholdEcdsaSessionRecordForSigning({
      nearAccountId: ACCOUNT_ID,
      chain: 'evm',
    });
    expect(record.source).toBe('manual-bootstrap');
    expect(record.ecdsaThresholdKeyId).toBe('ehss-link-device-1');

    await expectOneKeyEcdsaExportFromEngine({
      engine,
      expectedEcdsaThresholdKeyId: 'ehss-link-device-1',
      expectedJwt: 'jwt:ecdsa-link-device-1',
      exportWorkerCalls,
    });
  });
});

import { test, expect } from '@playwright/test';
import * as ed from '@noble/ed25519';
import bs58 from 'bs58';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ActionType, type ActionArgsWasm } from '@/core/types/actions';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { threshold_ed25519_compute_near_tx_signing_digests } from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  callCf,
  fetchJson,
  getPath,
  makeCfCtx,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';
import { deriveThresholdEd25519VerifyingShareForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import type {
  ThresholdEd25519AuthConsumeUsesResult,
  Ed25519AuthSessionRecord,
  Ed25519AuthSessionStore,
} from '@server/core/ThresholdService/stores/AuthSessionStore';

type ThresholdEd25519AuthConsumeResult =
  | { ok: true; record: Ed25519AuthSessionRecord; remainingUses: number }
  | { ok: false; code: string; message: string };

const DEFAULT_ECDSA_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString(
  'base64url',
);
const DEFAULT_ED25519_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(7)).toString(
  'base64url',
);

function makeAuthServiceForThreshold(): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const thresholdConfig = {
    THRESHOLD_NODE_ROLE: 'coordinator',
    THRESHOLD_ED25519_MASTER_SECRET_B64U: DEFAULT_ED25519_MASTER_SECRET_B64U,
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: DEFAULT_ECDSA_MASTER_SECRET_B64U,
  } as const;
  const svc = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    thresholdEd25519KeyStore: thresholdConfig,
    logger: null,
  });

  // Avoid network calls in threshold session/signing tests.
  (
    svc as unknown as {
      verifyWebAuthnAuthenticationLite: (
        req: any,
      ) => Promise<{ success: boolean; verified: boolean }>;
    }
  ).verifyWebAuthnAuthenticationLite = async (_req: any) => ({ success: true, verified: true });

  // Avoid network calls for access key list checks. Tests set `__testAllowedNearPublicKey`
  // when they provision registration material directly.
  (svc as unknown as { __testAllowedNearPublicKey?: string }).__testAllowedNearPublicKey = '';
  (
    svc as unknown as { nearClient: { viewAccessKeyList: (accountId: string) => Promise<unknown> } }
  ).nearClient.viewAccessKeyList = async (_accountId: string) => {
    const key = String(
      (svc as unknown as { __testAllowedNearPublicKey?: string }).__testAllowedNearPublicKey || '',
    ).trim();
    if (!key) return { keys: [] };
    return { keys: [{ public_key: key, access_key: { nonce: 0, permission: 'FullAccess' } }] };
  };

  const threshold = createThresholdSigningService({
    authService: svc,
    thresholdEd25519KeyStore: thresholdConfig,
    logger: null,
  });

  return { service: svc, threshold };
}

async function randomClientVerifyingShareB64u(): Promise<string> {
  const sk = crypto.getRandomValues(new Uint8Array(32));
  const pk = await ed.getPublicKeyAsync(sk);
  return base64UrlEncode(pk);
}

function randomBytes32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

function scalarToLittleEndianBytes32(value: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let remaining = value;
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function toBase64UrlUtf8(json: string): string {
  const b64 = Buffer.from(json, 'utf8').toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromBase64UrlUtf8(b64u: string): string {
  const padded =
    b64u.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (b64u.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function createTestSessionAdapter(): {
  session: ReturnType<typeof makeSessionAdapter>;
} {
  const session = makeSessionAdapter({
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const claims = { sub, ...(extra || {}) };
      return `testjwt-${toBase64UrlUtf8(JSON.stringify(claims))}`;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers['authorization'] ?? headers['Authorization'];
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const token =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      if (!token.startsWith('testjwt-')) {
        return { ok: false as const };
      }
      try {
        const json = fromBase64UrlUtf8(token.slice('testjwt-'.length));
        const claims = JSON.parse(json) as unknown;
        if (!claims || typeof claims !== 'object' || Array.isArray(claims))
          return { ok: false as const };
        return { ok: true as const, claims: claims as Record<string, unknown> };
      } catch {
        return { ok: false as const };
      }
    },
  });
  return { session };
}

function enableOidcExchangeForTest(service: AuthService, userId: string): void {
  (
    service as unknown as { verifyOidcJwtExchange: AuthService['verifyOidcJwtExchange'] }
  ).verifyOidcJwtExchange = async (request: { token?: unknown }) => {
    const token = String(request?.token || '').trim();
    if (!token) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_body',
        message: 'exchange.token is required',
      };
    }
    return {
      ok: true,
      verified: true,
      userId,
      providerSubject: `oidc:${userId}`,
      iss: 'https://issuer.test',
      aud: ['relay-client-test'],
      sub: userId,
    };
  };
}

function testWebauthnAuthenticationPayload(): Record<string, unknown> {
  return {
    id: 'test',
    rawId: 'test',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'test',
      authenticatorData: 'test',
      signature: 'test',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

class SplitAuthSessionStore implements Ed25519AuthSessionStore {
  readonly records = new Map<string, Ed25519AuthSessionRecord>();
  readonly uses = new Map<string, number>();
  consumeUseCalls = 0;
  consumeUseCountCalls = 0;

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    this.records.set(id, record);
    this.uses.set(id, Math.max(0, Number(opts.remainingUses) || 0));
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    return this.records.get(id) ?? null;
  }

  async consumeUse(id: string): Promise<ThresholdEd25519AuthConsumeResult> {
    this.consumeUseCalls += 1;
    const remainingUses = (this.uses.get(id) ?? 0) - 1;
    this.uses.set(id, remainingUses);
    if (remainingUses < 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
    }
    const record = await this.getSession(id);
    if (!record) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    }
    if (Date.now() > record.expiresAtMs) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    return { ok: true, record, remainingUses };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    this.consumeUseCountCalls += 1;
    const remainingUses = (this.uses.get(id) ?? 0) - 1;
    this.uses.set(id, remainingUses);
    if (remainingUses < 0) {
      return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
    }
    return { ok: true, remainingUses };
  }
}

async function buildThresholdSessionBody(input: {
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  nearAccountId: string;
  rpId: string;
  sessionId: string;
  ttlMs: number;
  remainingUses: number;
}): Promise<Record<string, unknown>> {
  const policy = {
    version: 'threshold_session_v1',
    nearAccountId: input.nearAccountId,
    rpId: input.rpId,
    relayerKeyId: input.relayerKeyId,
    sessionId: input.sessionId,
    ttlMs: input.ttlMs,
    remainingUses: input.remainingUses,
  };

  return {
    relayerKeyId: input.relayerKeyId,
    clientVerifyingShareB64u: input.clientVerifyingShareB64u,
    sessionPolicy: policy,
    sessionKind: 'jwt',
    webauthn_authentication: testWebauthnAuthenticationPayload(),
  };
}

async function buildNearTxAuthorizeBody(input: {
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  nearAccountId: string;
  nearPublicKeyStr: string;
  receiverId: string;
  actions: ActionArgsWasm[];
}): Promise<{ body: Record<string, unknown>; signingDigestB64u: string }> {
  const txSigningRequests = [
    {
      nearAccountId: input.nearAccountId,
      receiverId: input.receiverId,
      actions: input.actions,
    },
  ];
  const txBlockHashBytes = randomBytes32();
  const signingPayload = {
    kind: 'near_tx',
    txSigningRequests,
    transactionContext: {
      nearPublicKeyStr: input.nearPublicKeyStr,
      nextNonce: '1',
      txBlockHeight: '1',
      txBlockHash: bs58.encode(txBlockHashBytes),
    },
  };

  const digestsUnknown: unknown = threshold_ed25519_compute_near_tx_signing_digests(signingPayload);
  if (!Array.isArray(digestsUnknown) || !digestsUnknown.length) {
    throw new Error('Failed to compute near_tx signing digest via WASM');
  }
  const first = digestsUnknown[0];
  const signingDigestBytes = first instanceof Uint8Array ? first : null;
  if (!signingDigestBytes || signingDigestBytes.length !== 32) {
    throw new Error('Failed to compute near_tx signing digest via WASM');
  }

  return {
    signingDigestB64u: base64UrlEncode(signingDigestBytes),
    body: {
      relayerKeyId: input.relayerKeyId,
      clientVerifyingShareB64u: input.clientVerifyingShareB64u,
      purpose: 'near_tx',
      signing_digest_32: Array.from(signingDigestBytes),
      signingPayload,
    },
  };
}

const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

async function provisionThresholdEd25519RegistrationMaterial(input: {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
  nearAccountId: string;
  rpId?: string;
  publicKey?: string;
}): Promise<{ relayerKeyId: string; nearPublicKeyStr: string }> {
  const nearPublicKeyStr = input.publicKey ?? `ed25519:${bs58.encode(randomBytes32())}`;
  const relayerScalar = scalarToLittleEndianBytes32(
    (await ed.utils.getExtendedPublicKeyAsync(randomBytes32())).scalar,
  );
  const relayerSigningShareB64u = base64UrlEncode(relayerScalar);
  const relayerVerifyingShareB64u = deriveThresholdEd25519VerifyingShareForUnitTests({
    signingShareB64u: relayerSigningShareB64u,
  });
  await (
    input.threshold as unknown as {
      keyStore: { put: (keyId: string, value: unknown) => Promise<void> };
    }
  ).keyStore.put(nearPublicKeyStr, {
    nearAccountId: input.nearAccountId,
    rpId: input.rpId ?? 'example.localhost',
    publicKey: nearPublicKeyStr,
    relayerSigningShareB64u,
    relayerVerifyingShareB64u,
    keyVersion: THRESHOLD_ED25519_KEY_VERSION_V1,
    recoveryExportCapable: true,
  });
  (input.service as unknown as { __testAllowedNearPublicKey?: string }).__testAllowedNearPublicKey =
    nearPublicKeyStr;
  return {
    relayerKeyId: nearPublicKeyStr,
    nearPublicKeyStr,
  };
}

test.describe('threshold-ed25519 scope (express)', () => {
  test('integration: session/exchange -> threshold session -> authorize -> sign/init', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    enableOidcExchangeForTest(service, 'bob.testnet');

    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const exchanged = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
        }),
      });
      expect(exchanged.status, exchanged.text).toBe(200);
      expect(exchanged.json?.ok, exchanged.text).toBe(true);
      const appJwt = String(exchanged.json?.jwt || '');
      expect(appJwt).toContain('testjwt-');

      const state = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${appJwt}` },
      });
      expect(state.status, state.text).toBe(200);
      expect(state.json?.authenticated, state.text).toBe(true);
      expect(getPath(state.json, 'claims', 'kind')).toBe('app_session_v1');

      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const thresholdSessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 2,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(thresholdSessionBody),
      });
      expect(minted.status, minted.text).toBe(200);
      expect(minted.json?.ok, minted.text).toBe(true);
      const thresholdJwt = String(minted.json?.jwt || '');
      expect(thresholdJwt).toContain('testjwt-');

      const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const auth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${thresholdJwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth.status, auth.text).toBe(200);
      expect(auth.json?.ok, auth.text).toBe(true);
      const mpcSessionId = String(auth.json?.mpcSessionId || '');
      expect(mpcSessionId).toContain('mpc-');

      const signInit = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(signInit.status, signInit.text).toBe(200);
      expect(signInit.json?.ok, signInit.text).toBe(true);
      expect(String(signInit.json?.signingSessionId || '')).toContain('sign-');
    } finally {
      await srv.close();
    }
  });

  test('integration: wallet/unlock/challenge -> session/exchange(passkey_assertion) -> session/state -> threshold session -> authorize -> sign/init -> revoke', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const unlockOptions = await fetchJson(`${srv.baseUrl}/wallet/unlock/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: 'bob.testnet',
          rp_id: 'example.localhost',
        }),
      });
      expect(unlockOptions.status, unlockOptions.text).toBe(200);
      expect(unlockOptions.json?.ok, unlockOptions.text).toBe(true);
      const challengeId = String(unlockOptions.json?.challengeId || '').trim();
      expect(challengeId).not.toBe('');

      const exchanged = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify({
          sessionKind: 'jwt',
          exchange: {
            type: 'passkey_assertion',
            challengeId,
            webauthn_authentication: testWebauthnAuthenticationPayload(),
          },
        }),
      });
      expect(exchanged.status, exchanged.text).toBe(200);
      expect(exchanged.json?.ok, exchanged.text).toBe(true);
      const appJwt = String(exchanged.json?.jwt || '');
      expect(appJwt).toContain('testjwt-');

      const state = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${appJwt}` },
      });
      expect(state.status, state.text).toBe(200);
      expect(state.json?.authenticated, state.text).toBe(true);
      expect(getPath(state.json, 'claims', 'kind')).toBe('app_session_v1');

      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const thresholdSessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 2,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(thresholdSessionBody),
      });
      expect(minted.status, minted.text).toBe(200);
      expect(minted.json?.ok, minted.text).toBe(true);
      const thresholdJwt = String(minted.json?.jwt || '');
      expect(thresholdJwt).toContain('testjwt-');

      const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const auth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${thresholdJwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth.status, auth.text).toBe(200);
      expect(auth.json?.ok, auth.text).toBe(true);
      const mpcSessionId = String(auth.json?.mpcSessionId || '');
      expect(mpcSessionId).toContain('mpc-');

      const signInit = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(signInit.status, signInit.text).toBe(200);
      expect(signInit.json?.ok, signInit.text).toBe(true);
      expect(String(signInit.json?.signingSessionId || '')).toContain('sign-');

      const revoke = await fetchJson(`${srv.baseUrl}/session/revoke`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${appJwt}` },
      });
      expect(revoke.status, revoke.text).toBe(200);
      expect(revoke.json?.ok, revoke.text).toBe(true);

      const staleState = await fetchJson(`${srv.baseUrl}/session/state`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${appJwt}` },
      });
      expect(staleState.status, staleState.text).toBe(401);
      expect(staleState.json?.code, staleState.text).toBe('invalid_session_version');
    } finally {
      await srv.close();
    }
  });

  test('threshold session: authorize uses JWT claims (no KV record read)', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const splitStore = new SplitAuthSessionStore();
    (threshold as any).authSessionStore = splitStore;

    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 1,
      });

      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toContain('testjwt-');

      // Simulate an eventually-consistent KV read where the session "record" is temporarily missing,
      // but the use counter exists and can be decremented.
      splitStore.records.delete(sessionId);

      const { body: authorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });

      const auth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth.status, auth.text).toBe(200);
      expect(auth.json?.ok, auth.text).toBe(true);
      expect(splitStore.consumeUseCountCalls).toBe(1);
      expect(splitStore.consumeUseCalls).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('threshold session: remainingUses decrements and exhausts', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 1,
      });

      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toContain('testjwt-');

      const { body: authorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });

      const auth1 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth1.status, auth1.text).toBe(200);
      expect(auth1.json?.ok, auth1.text).toBe(true);

      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth2.status).toBe(401);
      expect(auth2.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('threshold session: mint replay does not reset remainingUses', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 2,
      });

      const minted1 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted1.status).toBe(200);
      expect(minted1.json?.ok).toBe(true);
      const jwt1 = String(minted1.json?.jwt || '');
      expect(jwt1).toContain('testjwt-');

      const { body: authorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });

      const auth1 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt1}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth1.status, auth1.text).toBe(200);
      expect(auth1.json?.ok, auth1.text).toBe(true);

      // Replay /session (same sessionId/policy): should not reset the server-side remainingUses budget.
      const minted2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted2.status).toBe(200);
      expect(minted2.json?.ok).toBe(true);
      const jwt2 = String(minted2.json?.jwt || '');
      expect(jwt2).toContain('testjwt-');

      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt2}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth2.status).toBe(200);
      expect(auth2.json?.ok).toBe(true);

      // Third authorize should fail (2 uses total, even after replaying /session).
      const auth3 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt2}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth3.status).toBe(401);
      expect(auth3.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('authorize binds signing digest; mpcSessionId is single-use; finalize discards signingSessionId', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });
      expect(relayerKeyId).toContain('ed25519:');
      expect(nearPublicKeyStr).toContain('ed25519:');

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 5,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toContain('testjwt-');

      const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const auth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth.status).toBe(200);
      expect(auth.json?.ok).toBe(true);
      const mpcSessionId = String(auth.json?.mpcSessionId || '');
      expect(mpcSessionId).toContain('mpc-');

      const init = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(init.status).toBe(200);
      expect(init.json?.ok).toBe(true);
      const signingSessionId = String(init.json?.signingSessionId || '');
      expect(signingSessionId).toContain('sign-');

      // mpcSessionId is one-shot after a successful /sign/init.
      const initReplay = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(initReplay.status).toBe(401);
      expect(initReplay.json?.code).toBe('unauthorized');

      // finalize always consumes signingSessionId (even on invalid inputs) to avoid nonce reuse.
      const finalize1 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signingSessionId, clientSignatureShareB64u: 'not-base64url' }),
      });
      expect([400, 401, 500]).toContain(finalize1.status);

      const finalize2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ signingSessionId, clientSignatureShareB64u: 'not-base64url' }),
      });
      expect(finalize2.status).toBe(401);
      expect(finalize2.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('sign/init rejects digest mismatch and nearAccountId mismatch', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 3,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toContain('testjwt-');

      const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const digestB = randomBytes32();

      const auth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth.status).toBe(200);
      const mpcSessionId = String(auth.json?.mpcSessionId || '');

      const badDigest = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u: base64UrlEncode(digestB),
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(badDigest.status).toBe(401);
      expect(badDigest.json?.code).toBe('unauthorized');

      // New authorization for account mismatch check.
      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(authorizeBody),
      });
      expect(auth2.status).toBe(200);
      const mpc2 = String(auth2.json?.mpcSessionId || '');

      const badAccount = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId: mpc2,
          relayerKeyId,
          nearAccountId: 'alice.testnet',
          signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(badAccount.status).toBe(401);
      expect(badAccount.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('authorize rejects missing signing_digest_32', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId, nearPublicKeyStr } =
        await provisionThresholdEd25519RegistrationMaterial({
          service,
          threshold,
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
        });

      const sessionId = `sess-${Date.now()}`;
      const sessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId,
        ttlMs: 60_000,
        remainingUses: 1,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      expect(jwt).toContain('testjwt-');

      const res = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          clientVerifyingShareB64u,
          purpose: 'near_tx',
        }),
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });
});

test.describe('threshold-ed25519 scope (cloudflare)', () => {
  test('integration: session/exchange -> threshold session -> authorize -> sign/init', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    enableOidcExchangeForTest(service, 'bob.testnet');

    const { session } = createTestSessionAdapter();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      threshold,
      session,
    });
    const { ctx } = makeCfCtx();

    const exchanged = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: { type: 'oidc_jwt', token: 'header.payload.signature' },
      },
      ctx,
    });
    expect(exchanged.status, exchanged.text).toBe(200);
    expect(exchanged.json?.ok, exchanged.text).toBe(true);
    const appJwt = String(exchanged.json?.jwt || '');
    expect(appJwt).toContain('testjwt-');

    const state = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${appJwt}` },
      ctx,
    });
    expect(state.status, state.text).toBe(200);
    expect(state.json?.authenticated, state.text).toBe(true);
    expect(getPath(state.json, 'claims', 'kind')).toBe('app_session_v1');

    const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
    const { relayerKeyId, nearPublicKeyStr } = await provisionThresholdEd25519RegistrationMaterial({
      service,
      threshold,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
    });

    const sessionId = `sess-${Date.now()}`;
    const thresholdSessionBody = await buildThresholdSessionBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
      sessionId,
      ttlMs: 60_000,
      remainingUses: 2,
    });

    const minted = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/session',
      origin: 'https://example.localhost',
      body: thresholdSessionBody,
      ctx,
    });
    expect(minted.status, minted.text).toBe(200);
    expect(minted.json?.ok, minted.text).toBe(true);
    const thresholdJwt = String(minted.json?.jwt || '');
    expect(thresholdJwt).toContain('testjwt-');

    const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      nearPublicKeyStr,
      receiverId: 'receiver.testnet',
      actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
    });
    const auth = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${thresholdJwt}` },
      body: authorizeBody,
      ctx,
    });
    expect(auth.status, auth.text).toBe(200);
    expect(auth.json?.ok, auth.text).toBe(true);
    const mpcSessionId = String(auth.json?.mpcSessionId || '');
    expect(mpcSessionId).toContain('mpc-');

    const signInit = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/init',
      origin: 'https://example.localhost',
      body: {
        mpcSessionId,
        relayerKeyId,
        nearAccountId: 'bob.testnet',
        signingDigestB64u,
        clientCommitments: { hiding: 'a', binding: 'b' },
      },
      ctx,
    });
    expect(signInit.status, signInit.text).toBe(200);
    expect(signInit.json?.ok, signInit.text).toBe(true);
    expect(String(signInit.json?.signingSessionId || '')).toContain('sign-');
  });

  test('integration: wallet/unlock/challenge -> session/exchange(passkey_assertion) -> session/state -> threshold session -> authorize -> sign/init -> revoke', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      threshold,
      session,
    });
    const { ctx } = makeCfCtx();

    const unlockOptions = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/challenge',
      origin: 'https://example.localhost',
      body: {
        user_id: 'bob.testnet',
        rp_id: 'example.localhost',
      },
      ctx,
    });
    expect(unlockOptions.status, unlockOptions.text).toBe(200);
    expect(unlockOptions.json?.ok, unlockOptions.text).toBe(true);
    const challengeId = String(unlockOptions.json?.challengeId || '').trim();
    expect(challengeId).not.toBe('');

    const exchanged = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: 'https://example.localhost',
      body: {
        sessionKind: 'jwt',
        exchange: {
          type: 'passkey_assertion',
          challengeId,
          webauthn_authentication: testWebauthnAuthenticationPayload(),
        },
      },
      ctx,
    });
    expect(exchanged.status, exchanged.text).toBe(200);
    expect(exchanged.json?.ok, exchanged.text).toBe(true);
    const appJwt = String(exchanged.json?.jwt || '');
    expect(appJwt).toContain('testjwt-');

    const state = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${appJwt}` },
      ctx,
    });
    expect(state.status, state.text).toBe(200);
    expect(state.json?.authenticated, state.text).toBe(true);
    expect(getPath(state.json, 'claims', 'kind')).toBe('app_session_v1');

    const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
    const { relayerKeyId, nearPublicKeyStr } = await provisionThresholdEd25519RegistrationMaterial({
      service,
      threshold,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
    });

    const sessionId = `sess-${Date.now()}`;
    const thresholdSessionBody = await buildThresholdSessionBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
      sessionId,
      ttlMs: 60_000,
      remainingUses: 2,
    });
    const minted = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/session',
      origin: 'https://example.localhost',
      body: thresholdSessionBody,
      ctx,
    });
    expect(minted.status, minted.text).toBe(200);
    expect(minted.json?.ok, minted.text).toBe(true);
    const thresholdJwt = String(minted.json?.jwt || '');
    expect(thresholdJwt).toContain('testjwt-');

    const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      nearPublicKeyStr,
      receiverId: 'receiver.testnet',
      actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
    });
    const auth = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${thresholdJwt}` },
      body: authorizeBody,
      ctx,
    });
    expect(auth.status, auth.text).toBe(200);
    expect(auth.json?.ok, auth.text).toBe(true);
    const mpcSessionId = String(auth.json?.mpcSessionId || '');
    expect(mpcSessionId).toContain('mpc-');

    const signInit = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/init',
      origin: 'https://example.localhost',
      body: {
        mpcSessionId,
        relayerKeyId,
        nearAccountId: 'bob.testnet',
        signingDigestB64u,
        clientCommitments: { hiding: 'a', binding: 'b' },
      },
      ctx,
    });
    expect(signInit.status, signInit.text).toBe(200);
    expect(signInit.json?.ok, signInit.text).toBe(true);
    expect(String(signInit.json?.signingSessionId || '')).toContain('sign-');

    const revoke = await callCf(handler, {
      method: 'POST',
      path: '/session/revoke',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${appJwt}` },
      ctx,
    });
    expect(revoke.status, revoke.text).toBe(200);
    expect(revoke.json?.ok, revoke.text).toBe(true);

    const staleState = await callCf(handler, {
      method: 'GET',
      path: '/session/state',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${appJwt}` },
      ctx,
    });
    expect(staleState.status, staleState.text).toBe(401);
    expect(staleState.json?.code, staleState.text).toBe('invalid_session_version');
  });

  test('threshold session: remainingUses decrements and exhausts', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      threshold,
      session,
    });
    const { ctx } = makeCfCtx();

    const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
    const { relayerKeyId, nearPublicKeyStr } = await provisionThresholdEd25519RegistrationMaterial({
      service,
      threshold,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
    });

    const sessionId = `sess-${Date.now()}`;
    const sessionBody = await buildThresholdSessionBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
      sessionId,
      ttlMs: 60_000,
      remainingUses: 1,
    });

    const minted = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/session',
      origin: 'https://example.localhost',
      body: sessionBody,
      ctx,
    });
    expect(minted.status).toBe(200);
    expect(minted.json?.ok).toBe(true);
    const jwt = String(minted.json?.jwt || '');
    expect(jwt).toContain('testjwt-');

    const { body: authorizeBody } = await buildNearTxAuthorizeBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      nearPublicKeyStr,
      receiverId: 'receiver.testnet',
      actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
    });

    const auth1 = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${jwt}` },
      body: authorizeBody,
      ctx,
    });
    expect(auth1.status, auth1.text).toBe(200);
    expect(auth1.json?.ok, auth1.text).toBe(true);

    const auth2 = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${jwt}` },
      body: authorizeBody,
      ctx,
    });
    expect(auth2.status).toBe(401);
    expect(auth2.json?.code).toBe('unauthorized');
  });

  test('mpcSessionId and signingSessionId scopes are enforced', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      threshold,
      session,
    });
    const { ctx } = makeCfCtx();

    const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
    const { relayerKeyId, nearPublicKeyStr } = await provisionThresholdEd25519RegistrationMaterial({
      service,
      threshold,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
    });

    const sessionId = `sess-${Date.now()}`;
    const sessionBody = await buildThresholdSessionBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
      sessionId,
      ttlMs: 60_000,
      remainingUses: 3,
    });
    const minted = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/session',
      origin: 'https://example.localhost',
      body: sessionBody,
      ctx,
    });
    expect(minted.status).toBe(200);
    expect(minted.json?.ok).toBe(true);
    const jwt = String(minted.json?.jwt || '');
    expect(jwt).toContain('testjwt-');

    const { body: authorizeBody, signingDigestB64u } = await buildNearTxAuthorizeBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      nearPublicKeyStr,
      receiverId: 'receiver.testnet',
      actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
    });
    const auth = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${jwt}` },
      body: authorizeBody,
      ctx,
    });
    expect(auth.status).toBe(200);
    expect(auth.json?.ok).toBe(true);
    const mpcSessionId = String(auth.json?.mpcSessionId || '');

    const init = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/init',
      origin: 'https://example.localhost',
      body: {
        mpcSessionId,
        relayerKeyId,
        nearAccountId: 'bob.testnet',
        signingDigestB64u,
        clientCommitments: { hiding: 'a', binding: 'b' },
      },
      ctx,
    });
    expect(init.status).toBe(200);
    expect(init.json?.ok).toBe(true);
    const signingSessionId = String(init.json?.signingSessionId || '');

    const initReplay = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/init',
      origin: 'https://example.localhost',
      body: {
        mpcSessionId,
        relayerKeyId,
        nearAccountId: 'bob.testnet',
        signingDigestB64u,
        clientCommitments: { hiding: 'a', binding: 'b' },
      },
      ctx,
    });
    expect(initReplay.status).toBe(401);
    expect(initReplay.json?.code).toBe('unauthorized');

    const finalize1 = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/finalize',
      origin: 'https://example.localhost',
      body: { signingSessionId, clientSignatureShareB64u: 'not-base64url' },
      ctx,
    });
    expect([400, 401, 500]).toContain(finalize1.status);

    const finalize2 = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/sign/finalize',
      origin: 'https://example.localhost',
      body: { signingSessionId, clientSignatureShareB64u: 'not-base64url' },
      ctx,
    });
    expect(finalize2.status).toBe(401);
    expect(finalize2.json?.code).toBe('unauthorized');
  });
});

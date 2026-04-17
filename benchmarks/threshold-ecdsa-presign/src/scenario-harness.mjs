#!/usr/bin/env node
import http from 'node:http';
import fs from 'node:fs';
import expressImport from 'express';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { createRelayRouter } from '../../../sdk/dist/esm/server/router/express.js';
import { AuthService, createThresholdSigningService } from '../../../sdk/dist/esm/server/index.js';
import { ThresholdEcdsaSigningHandlers } from '../../../sdk/dist/esm/server/core/ThresholdService/ecdsaSigningHandlers.js';
import { createThresholdEcdsaSigningStores } from '../../../sdk/dist/esm/server/core/ThresholdService/stores/EcdsaSigningStore.js';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../../sdk/dist/esm/server/core/ThresholdService/schemes/schemeIds.js';
import {
  alphabetizeStringify,
  sha256BytesUtf8,
} from '../../../sdk/dist/esm/shared/src/utils/digests.js';
import {
  addSecp256k1PublicKeys33,
  deriveThresholdSecp256k1RelayerShare,
} from '../../../sdk/dist/esm/server/core/ThresholdService/ethSignerWasm.js';
import {
  initSync as initEthSignerWasmSync,
  ThresholdEcdsaPresignSession,
  map_additive_share_to_threshold_signatures_share_2p,
  threshold_ecdsa_compute_signature_share,
} from '../../../wasm/eth_signer/pkg/eth_signer.js';
import { base64UrlEncode, base64UrlDecode } from '../../../sdk/dist/esm/shared/src/utils/base64.js';

const TEST_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');
const DEFAULT_PARTICIPANT_IDS = [1, 2];
const DEFAULT_CLIENT_PARTICIPANT_ID = 1;
const DEFAULT_RELAYER_PARTICIPANT_ID = 2;
const MAX_HANDSHAKE_STEPS = 64;

function parseArgs(argv) {
  const out = {
    scenario: 'cold_first_sign_no_pool',
    iterations: 1,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--scenario' && argv[i + 1]) {
      out.scenario = String(argv[++i]).trim();
      continue;
    }
    if (token === '--iterations' && argv[i + 1]) {
      out.iterations = Math.max(1, Math.floor(Number(argv[++i] || 1)));
      continue;
    }
  }
  return out;
}

function createLogger() {
  return {
    debug(msg, meta) {
      if (meta && typeof meta === 'object') console.log(msg, meta);
      else console.log(msg);
    },
    info(msg, meta) {
      if (meta && typeof meta === 'object') console.log(msg, meta);
      else console.log(msg);
    },
    warn(msg, meta) {
      if (meta && typeof meta === 'object') console.warn(msg, meta);
      else console.warn(msg);
    },
    error(msg, meta) {
      if (meta && typeof meta === 'object') console.error(msg, meta);
      else console.error(msg);
    },
  };
}

function randomUuidLike(prefix) {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return `${prefix}-${c.randomUUID()}`;
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function randomSecpSecretKey32() {
  const utils = secp256k1?.utils;
  if (typeof utils?.randomPrivateKey === 'function') return utils.randomPrivateKey();
  if (typeof utils?.randomSecretKey === 'function') return utils.randomSecretKey();
  throw new Error('secp256k1 random secret key generator is unavailable');
}

function randomDigest32() {
  const out = new Uint8Array(32);
  globalThis.crypto.getRandomValues(out);
  return out;
}

function toB64uMessages(messages) {
  return messages.map((entry) => base64UrlEncode(entry));
}

function fromB64uMessages(messagesB64u) {
  if (!Array.isArray(messagesB64u)) return [];
  return messagesB64u
    .map((entry) => String(entry || '').trim())
    .filter((entry) => Boolean(entry))
    .map((entry) => base64UrlDecode(entry));
}

async function deriveRelayerKeyId(input) {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: 'threshold_secp256k1_key_id_v1',
      schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
      userId: input.userId,
      rpId: input.rpId,
      clientVerifyingShareB64u: input.clientVerifyingShareB64u,
    }),
  );
  return `secp-${base64UrlEncode(digest32)}`;
}

async function deriveGroupPublicKey33(input) {
  const relayerShare = await deriveThresholdSecp256k1RelayerShare({
    masterSecretB64u: TEST_MASTER_SECRET_B64U,
    relayerKeyId: input.relayerKeyId,
  });
  return await addSecp256k1PublicKeys33({
    left33: input.clientVerifyingShare33,
    right33: relayerShare.relayerVerifyingShare33,
  });
}

function mapStatusFromResult(result) {
  if (result?.ok === true) return 200;
  const code = String(result?.code || '').trim();
  if (code === 'unauthorized' || code === 'forbidden') return 401;
  if (code === 'not_found') return 404;
  if (code === 'internal') return 500;
  return 400;
}

async function invokeHandlerWithRouteLog(input) {
  const startedAtMs = Date.now();
  console.log('[threshold-ecdsa] request', {
    route: input.route,
    method: 'INTERNAL',
    ...(input.requestMeta || {}),
  });
  const result = await input.fn();
  console.log('[threshold-ecdsa] response', {
    route: input.route,
    status: mapStatusFromResult(result),
    ok: Boolean(result?.ok),
    durationMs: Math.max(0, Date.now() - startedAtMs),
    ...(result?.code ? { code: result.code } : {}),
  });
  return result;
}

function createCacheMissHandlers(input) {
  const baseLogger = input.logger || {
    debug(msg, meta) {
      if (meta && typeof meta === 'object') console.log(msg, meta);
      else console.log(msg);
    },
    info(msg, meta) {
      if (meta && typeof meta === 'object') console.log(msg, meta);
      else console.log(msg);
    },
    warn(msg, meta) {
      if (meta && typeof meta === 'object') console.warn(msg, meta);
      else console.warn(msg);
    },
    error(msg, meta) {
      if (meta && typeof meta === 'object') console.error(msg, meta);
      else console.error(msg);
    },
  };
  const logger = {
    debug: (...args) => baseLogger.debug(...args),
    info: (...args) => baseLogger.info(...args),
    warn: (...args) => baseLogger.warn(...args),
    error: (...args) => baseLogger.error(...args),
  };
  const signingStores = createThresholdEcdsaSigningStores({
    config: { kind: 'in-memory' },
    logger,
    isNode: true,
  });

  const fakeSessionStore = {
    putMpcSession: async () => {},
    takeMpcSession: async () => null,
    putSigningSession: async () => {},
    takeSigningSession: async () => null,
    putCoordinatorSigningSession: async () => {},
    takeCoordinatorSigningSession: async () => null,
  };

  let presignIdCounter = 0;
  const makeHandler = () =>
    new ThresholdEcdsaSigningHandlers({
      logger,
      nodeRole: 'coordinator',
      participantIds2p: input.participantIds,
      clientParticipantId: input.clientParticipantId,
      relayerParticipantId: input.relayerParticipantId,
      secp256k1MasterSecretB64u: TEST_MASTER_SECRET_B64U,
      sessionStore: fakeSessionStore,
      signingSessionStore: signingStores.signingSessionStore,
      presignSessionStore: signingStores.presignSessionStore,
      presignaturePool: signingStores.presignaturePool,
      ensureReady: async () => {},
      createSigningSessionId: () => randomUuidLike('bench-sign'),
      createPresignSessionId: () => `bench-presign-${++presignIdCounter}`,
    });

  return {
    handlerA: makeHandler(),
    handlerB: makeHandler(),
  };
}

function pollSession(session) {
  const raw = session.poll() || {};
  const stage =
    raw.stage === 'triples_done'
      ? 'triples_done'
      : raw.stage === 'presign'
        ? 'presign'
        : raw.stage === 'done'
          ? 'done'
          : 'triples';
  const event =
    raw.event === 'triples_done'
      ? 'triples_done'
      : raw.event === 'presign_done'
        ? 'presign_done'
        : 'none';
  const outgoingMessages = Array.isArray(raw.outgoing)
    ? raw.outgoing.map((entry) => {
        if (entry instanceof Uint8Array) return entry;
        if (entry instanceof ArrayBuffer) return new Uint8Array(entry);
        if (ArrayBuffer.isView(entry))
          return new Uint8Array(entry.buffer, entry.byteOffset, entry.byteLength);
        throw new Error('Unexpected presign outgoing message type');
      })
    : [];
  return { stage, event, outgoingMessages };
}

async function fetchJson(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  try {
    const parsed = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) json = parsed;
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

async function startExpressRouter(router) {
  const maybeDefault = expressImport?.default;
  const express = typeof maybeDefault === 'function' ? maybeDefault : expressImport;
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(router);

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Failed to bind benchmark server');
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}

function makeSessionAdapter() {
  const claimsByToken = new Map();
  return {
    signJwt: async (sub, extra) => {
      const token = randomUuidLike('bench-jwt');
      claimsByToken.set(token, { sub, ...(extra || {}) });
      return token;
    },
    parse: async (headers) => {
      const raw = headers?.authorization ?? headers?.Authorization;
      const auth = Array.isArray(raw) ? raw[0] : raw;
      const token = typeof auth === 'string' ? auth.replace(/^Bearer\s+/i, '').trim() : '';
      const claims = token ? claimsByToken.get(token) : null;
      return claims ? { ok: true, claims } : { ok: false };
    },
    buildSetCookie: (token) => `w3a_session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    buildClearCookie: () => 'w3a_session=; Path=/; Max-Age=0',
    refresh: async () => ({ ok: false, code: 'not_eligible', message: 'not eligible' }),
  };
}

function fakeWebAuthnAuthentication() {
  return {
    id: 'bench',
    rawId: 'bench',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'bench',
      authenticatorData: 'bench',
      signature: 'bench',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

function parseThresholdStoreConfigFromEnv() {
  const mode = String(process.env.BENCH_THRESHOLD_STORE_MODE || 'in-memory')
    .trim()
    .toLowerCase();
  const base = {
    THRESHOLD_NODE_ROLE: 'coordinator',
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: TEST_MASTER_SECRET_B64U,
  };
  if (mode === 'redis') {
    const redisUrl = String(process.env.BENCH_REDIS_URL || process.env.REDIS_URL || '').trim();
    if (!redisUrl) {
      console.warn(
        '[benchmark] BENCH_THRESHOLD_STORE_MODE=redis but REDIS_URL missing; falling back to in-memory',
      );
      return { kind: 'in-memory', ...base };
    }
    return { kind: 'redis-tcp', REDIS_URL: redisUrl, ...base };
  }
  if (mode === 'upstash') {
    const url = String(
      process.env.BENCH_UPSTASH_REDIS_REST_URL || process.env.UPSTASH_REDIS_REST_URL || '',
    ).trim();
    const token = String(
      process.env.BENCH_UPSTASH_REDIS_REST_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '',
    ).trim();
    if (!url || !token) {
      console.warn(
        '[benchmark] BENCH_THRESHOLD_STORE_MODE=upstash but Upstash env missing; falling back to in-memory',
      );
      return { kind: 'in-memory', ...base };
    }
    return {
      kind: 'upstash-rest',
      UPSTASH_REDIS_REST_URL: url,
      UPSTASH_REDIS_REST_TOKEN: token,
      ...base,
    };
  }
  if (mode === 'postgres') {
    const pgUrl = String(
      process.env.BENCH_PG_URL || process.env.POSTGRES_URL || process.env.DATABASE_URL || '',
    ).trim();
    if (!pgUrl) {
      console.warn(
        '[benchmark] BENCH_THRESHOLD_STORE_MODE=postgres but DB URL missing; falling back to in-memory',
      );
      return { kind: 'in-memory', ...base };
    }
    return { kind: 'postgres', POSTGRES_URL: pgUrl, ...base };
  }
  return { kind: 'in-memory', ...base };
}

function makeAuthServiceForThreshold(logger) {
  const service = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger,
  });

  service.verifyWebAuthnAuthenticationLite = async () => ({ success: true, verified: true });

  const threshold = createThresholdSigningService({
    authService: service,
    thresholdStore: parseThresholdStoreConfigFromEnv(),
    logger,
  });

  return { service, threshold };
}

async function bootstrapContext(baseUrl, userId, rpId, clientVerifyingShareB64u, participantIds) {
  const sessionId = randomUuidLike('bench-session');
  const bootstrap = await fetchJson(`${baseUrl}/threshold-ecdsa/bootstrap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId,
      rpId,
      keygenSessionId: randomUuidLike('bench-keygen'),
      clientVerifyingShareB64u,
      webauthn_authentication: fakeWebAuthnAuthentication(),
      sessionKind: 'jwt',
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId,
        rpId,
        sessionId,
        ttlMs: 120_000,
        remainingUses: 100,
        participantIds,
      },
    }),
  });
  if (bootstrap.status !== 200 || !bootstrap.json?.ok) {
    throw new Error(`bootstrap failed: ${bootstrap.text}`);
  }
  const jwt = String(bootstrap.json.jwt || '').trim();
  const relayerKeyId = String(bootstrap.json.relayerKeyId || '').trim();
  const groupPublicKeyB64u = String(bootstrap.json.groupPublicKeyB64u || '').trim();
  if (!jwt || !relayerKeyId || !groupPublicKeyB64u) {
    throw new Error(`bootstrap missing fields: ${bootstrap.text}`);
  }
  return {
    jwt,
    relayerKeyId,
    groupPublicKey33: base64UrlDecode(groupPublicKeyB64u),
  };
}

async function authorizeMpcSession(
  baseUrl,
  jwt,
  relayerKeyId,
  clientVerifyingShareB64u,
  digest32,
  purpose,
) {
  const authorized = await fetchJson(`${baseUrl}/threshold-ecdsa/authorize`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${jwt}`,
    },
    body: JSON.stringify({
      relayerKeyId,
      clientVerifyingShareB64u,
      purpose,
      signing_digest_32: Array.from(digest32),
    }),
  });
  if (authorized.status !== 200 || !authorized.json?.ok) {
    throw new Error(`authorize failed: ${authorized.text}`);
  }
  const mpcSessionId = String(authorized.json.mpcSessionId || '').trim();
  if (!mpcSessionId) throw new Error(`authorize missing mpcSessionId: ${authorized.text}`);
  return mpcSessionId;
}

async function runPresignHandshake(args) {
  const init = await fetchJson(`${args.baseUrl}/threshold-ecdsa/presign/init`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.jwt}`,
    },
    body: JSON.stringify({
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      count: 1,
      ...(args.requestTag ? { requestTag: args.requestTag } : {}),
    }),
  });
  if (init.status !== 200 || !init.json?.ok) {
    throw new Error(`presign/init failed: ${init.text}`);
  }

  const presignSessionId = String(init.json.presignSessionId || '').trim();
  if (!presignSessionId) throw new Error(`presign/init missing presignSessionId: ${init.text}`);

  const clientThresholdSigningShare32 = map_additive_share_to_threshold_signatures_share_2p(
    args.clientSigningShare32,
    args.clientParticipantId,
  );

  const localSession = new ThresholdEcdsaPresignSession(
    new Uint32Array(args.participantIds),
    args.clientParticipantId,
    2,
    clientThresholdSigningShare32,
    args.groupPublicKey33,
  );

  let localDonePresignature97 = null;
  let serverPresignatureId = null;
  let serverBigRB64u = null;
  let serverDone = false;
  let stageForServer = 'triples';
  let pendingClientOutgoing = [...pollSession(localSession).outgoingMessages];
  let pendingServerOutgoing = fromB64uMessages(init.json.outgoingMessagesB64u);

  try {
    for (let i = 0; i < MAX_HANDSHAKE_STEPS; i += 1) {
      if (pendingServerOutgoing.length > 0 && !localDonePresignature97) {
        if (stageForServer === 'presign' && localSession.stage() === 'triples_done') {
          localSession.start_presign();
        }
        for (const msg of pendingServerOutgoing) {
          localSession.message(args.relayerParticipantId, msg);
        }
        pendingServerOutgoing = [];
        const localPolled = pollSession(localSession);
        pendingClientOutgoing.push(...localPolled.outgoingMessages);
        if (
          localPolled.stage === 'triples_done' ||
          localPolled.stage === 'presign' ||
          localPolled.stage === 'done'
        ) {
          stageForServer = 'presign';
        }
        if (localPolled.event === 'presign_done') {
          localDonePresignature97 = localSession.take_presignature_97();
        }
      }

      if (!serverDone) {
        const step = await fetchJson(`${args.baseUrl}/threshold-ecdsa/presign/step`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${args.jwt}`,
          },
          body: JSON.stringify({
            presignSessionId,
            stage: stageForServer,
            outgoingMessagesB64u: toB64uMessages(pendingClientOutgoing),
            ...(args.requestTag ? { requestTag: args.requestTag } : {}),
          }),
        });
        if (step.status !== 200 || !step.json?.ok) {
          throw new Error(`presign/step failed: ${step.text}`);
        }
        pendingClientOutgoing = [];
        pendingServerOutgoing = fromB64uMessages(step.json.outgoingMessagesB64u);
        if (step.json.event === 'triples_done' || step.json.stage === 'presign') {
          stageForServer = 'presign';
        }
        if (step.json.event === 'presign_done') {
          serverDone = true;
          serverPresignatureId = String(step.json.presignatureId || '').trim();
          serverBigRB64u = String(step.json.bigRB64u || '').trim();
        }
      }

      if (localDonePresignature97 && serverDone && serverPresignatureId && serverBigRB64u) break;

      if (
        !pendingServerOutgoing.length &&
        !pendingClientOutgoing.length &&
        !localDonePresignature97
      ) {
        if (stageForServer === 'presign' && localSession.stage() === 'triples_done') {
          localSession.start_presign();
        }
        const localPolled = pollSession(localSession);
        pendingClientOutgoing.push(...localPolled.outgoingMessages);
        if (
          localPolled.stage === 'triples_done' ||
          localPolled.stage === 'presign' ||
          localPolled.stage === 'done'
        ) {
          stageForServer = 'presign';
        }
        if (localPolled.event === 'presign_done') {
          localDonePresignature97 = localSession.take_presignature_97();
        }
      }
    }

    if (!localDonePresignature97) throw new Error('local presign session did not finish');
    if (!serverPresignatureId || !serverBigRB64u)
      throw new Error('server presign session did not finish');
    if (localDonePresignature97.length !== 97) {
      throw new Error(`invalid local presignature length: ${localDonePresignature97.length}`);
    }

    const bigR33 = localDonePresignature97.slice(0, 33);
    const kShare32 = localDonePresignature97.slice(33, 65);
    const sigmaShare32 = localDonePresignature97.slice(65, 97);
    const localBigRB64u = base64UrlEncode(bigR33);
    if (localBigRB64u !== serverBigRB64u) {
      throw new Error('client/server presignature mismatch (bigR mismatch)');
    }

    return {
      presignatureId: serverPresignatureId,
      bigR33,
      kShare32,
      sigmaShare32,
      bigRB64u: localBigRB64u,
    };
  } finally {
    try {
      localSession.free();
    } catch {}
  }
}

async function signWithPresign(args) {
  const signingDigestB64u = base64UrlEncode(args.digest32);
  const signInit = await fetchJson(`${args.baseUrl}/threshold-ecdsa/sign/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      mpcSessionId: args.mpcSessionId,
      relayerKeyId: args.relayerKeyId,
      signingDigestB64u,
      clientRound1: { presignatureId: args.presignature.presignatureId },
    }),
  });
  if (signInit.status !== 200 || !signInit.json?.ok) {
    throw new Error(`sign/init failed: ${signInit.text}`);
  }
  const signingSessionId = String(signInit.json.signingSessionId || '').trim();
  const entropyB64u = String(signInit.json?.relayerRound1?.entropyB64u || '').trim();
  const relayerBigRB64u = String(signInit.json?.relayerRound1?.bigRB64u || '').trim();
  if (!signingSessionId || !entropyB64u)
    throw new Error(`sign/init missing fields: ${signInit.text}`);
  if (relayerBigRB64u && relayerBigRB64u !== args.presignature.bigRB64u) {
    throw new Error('relayer selected different presignature (bigR mismatch)');
  }

  const entropy32 = base64UrlDecode(entropyB64u);
  const clientSignatureShare32 = threshold_ecdsa_compute_signature_share(
    new Uint32Array(args.participantIds),
    args.clientParticipantId,
    args.groupPublicKey33,
    args.presignature.bigR33,
    args.presignature.kShare32,
    args.presignature.sigmaShare32,
    args.digest32,
    entropy32,
  );

  const finalize = await fetchJson(`${args.baseUrl}/threshold-ecdsa/sign/finalize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      signingSessionId,
      clientRound2: {
        clientSignatureShareB64u: base64UrlEncode(clientSignatureShare32),
      },
    }),
  });
  if (finalize.status !== 200 || !finalize.json?.ok) {
    throw new Error(`sign/finalize failed: ${finalize.text}`);
  }
  return finalize.json;
}

async function runSingleFlow(args) {
  const digest32 = randomDigest32();
  const mpcSessionId = await authorizeMpcSession(
    args.baseUrl,
    args.jwt,
    args.relayerKeyId,
    args.clientVerifyingShareB64u,
    digest32,
    args.purpose,
  );
  const presignature =
    args.presignature ||
    (await runPresignHandshake({
      baseUrl: args.baseUrl,
      jwt: args.jwt,
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      clientSigningShare32: args.clientSigningShare32,
      groupPublicKey33: args.groupPublicKey33,
      participantIds: args.participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
      requestTag: args.requestTag,
    }));
  await signWithPresign({
    baseUrl: args.baseUrl,
    mpcSessionId,
    relayerKeyId: args.relayerKeyId,
    digest32,
    presignature,
    participantIds: args.participantIds,
    clientParticipantId: args.clientParticipantId,
    groupPublicKey33: args.groupPublicKey33,
  });
  return true;
}

async function runLiveCacheMissHandshake(base) {
  const userId = 'bench-live-cache-miss.testnet';
  const rpId = 'example.localhost';
  const relayerKeyId = await deriveRelayerKeyId({
    userId,
    rpId,
    clientVerifyingShareB64u: base.clientVerifyingShareB64u,
  });

  const claims = {
    sub: userId,
    rpId,
    relayerKeyId,
    participantIds: base.participantIds,
    thresholdExpiresAtMs: Date.now() + 120_000,
  };

  const handlers = createCacheMissHandlers({
    participantIds: base.participantIds,
    clientParticipantId: base.clientParticipantId,
    relayerParticipantId: base.relayerParticipantId,
  });

  const init = await invokeHandlerWithRouteLog({
    route: '/threshold-ecdsa/presign/init',
    requestMeta: {
      relayerKeyId,
      clientVerifyingShareB64u_len: base.clientVerifyingShareB64u.length,
      count: 1,
    },
    fn: () =>
      handlers.handlerA.ecdsaPresignInit({
        claims,
        request: {
          relayerKeyId,
          clientVerifyingShareB64u: base.clientVerifyingShareB64u,
          count: 1,
        },
      }),
  });
  if (!init.ok) {
    throw new Error(`live-cache-miss init failed: ${init.message || init.code || 'unknown'}`);
  }

  const presignSessionId = String(init.presignSessionId || '').trim();
  if (!presignSessionId) throw new Error('live-cache-miss init missing presignSessionId');

  const step = await invokeHandlerWithRouteLog({
    route: '/threshold-ecdsa/presign/step',
    requestMeta: {
      presignSessionId,
      stage: 'triples',
      outgoingMessagesB64u_len: 0,
    },
    fn: () =>
      handlers.handlerB.ecdsaPresignStep({
        claims,
        request: {
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        },
      }),
  });
  if (step.ok) {
    throw new Error('live-cache-miss step unexpectedly succeeded on non-owning handler');
  }
  if (step.code !== 'stale_session_state') {
    throw new Error(`live-cache-miss expected stale_session_state, got ${step.code || 'unknown'}`);
  }
  return { staleSessionCount: 1 };
}

async function runScenario(base, scenario) {
  if (scenario === 'cold_first_sign_no_pool') {
    const startedAtMs = Date.now();
    await runSingleFlow({
      ...base,
      purpose: 'bench:cold_first_sign_no_pool',
    });
    return { scenario, totalMs: Date.now() - startedAtMs };
  }

  if (scenario === 'warm_sign_pool_hit') {
    const warmedPresignature = await runPresignHandshake({
      ...base,
      requestTag: 'background_presign_pool_refill',
    });
    const startedAtMs = Date.now();
    await runSingleFlow({
      ...base,
      purpose: 'bench:warm_sign_pool_hit',
      presignature: warmedPresignature,
    });
    return { scenario, totalMs: Date.now() - startedAtMs };
  }

  if (scenario === 'background_refill_contention') {
    const backgroundTask = runPresignHandshake({
      ...base,
      requestTag: 'background_presign_pool_refill',
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const startedAtMs = Date.now();
    await runSingleFlow({
      ...base,
      purpose: 'bench:background_refill_contention',
    });
    await backgroundTask;
    return { scenario, totalMs: Date.now() - startedAtMs };
  }

  if (scenario === 'multi_runtime_contention') {
    const bgA = runPresignHandshake({
      ...base,
      requestTag: 'background_presign_pool_refill',
    });
    const bgB = runPresignHandshake({
      ...base,
      requestTag: 'background_presign_pool_refill',
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    const startedAtMs = Date.now();
    await runSingleFlow({
      ...base,
      purpose: 'bench:multi_runtime_contention',
    });
    await Promise.all([bgA, bgB]);
    return { scenario, totalMs: Date.now() - startedAtMs };
  }

  if (scenario === 'store_backend_compare') {
    const startedAtMs = Date.now();
    await runSingleFlow({
      ...base,
      purpose: 'bench:store_backend_compare',
    });
    return {
      scenario,
      totalMs: Date.now() - startedAtMs,
      storeMode: String(process.env.BENCH_THRESHOLD_STORE_MODE || 'in-memory'),
    };
  }

  if (scenario === 'live_cache_miss_path') {
    const startedAtMs = Date.now();
    const miss = await runLiveCacheMissHandshake(base);
    return {
      scenario,
      totalMs: Date.now() - startedAtMs,
      staleSessionCount: miss.staleSessionCount,
    };
  }

  throw new Error(`unsupported scenario: ${scenario}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const wasmBytes = fs.readFileSync(
    new URL('../../../wasm/eth_signer/pkg/eth_signer_bg.wasm', import.meta.url),
  );
  initEthSignerWasmSync({ module: wasmBytes });
  const logger = createLogger();
  const { service, threshold } = makeAuthServiceForThreshold(logger);
  const session = makeSessionAdapter();
  const router = createRelayRouter(service, { threshold, session, logger });
  const server = await startExpressRouter(router);

  try {
    const userId = 'bench-user.testnet';
    const rpId = 'example.localhost';
    const participantIds = DEFAULT_PARTICIPANT_IDS.slice();
    const clientParticipantId = DEFAULT_CLIENT_PARTICIPANT_ID;
    const relayerParticipantId = DEFAULT_RELAYER_PARTICIPANT_ID;
    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShareB64u = base64UrlEncode(
      secp256k1.getPublicKey(clientSigningShare32, true),
    );
    const boot = await bootstrapContext(
      server.baseUrl,
      userId,
      rpId,
      clientVerifyingShareB64u,
      participantIds,
    );

    const runs = [];
    for (let i = 0; i < args.iterations; i += 1) {
      const run = await runScenario(
        {
          baseUrl: server.baseUrl,
          jwt: boot.jwt,
          relayerKeyId: boot.relayerKeyId,
          groupPublicKey33: boot.groupPublicKey33,
          participantIds,
          clientParticipantId,
          relayerParticipantId,
          clientSigningShare32,
          clientVerifyingShareB64u,
        },
        args.scenario,
      );
      runs.push(run);
    }

    const totalValues = runs
      .map((entry) => Number(entry.totalMs))
      .filter((value) => Number.isFinite(value));
    const meanMs =
      totalValues.length > 0
        ? totalValues.reduce((acc, value) => acc + value, 0) / totalValues.length
        : 0;
    const summary = {
      scenario: args.scenario,
      iterations: args.iterations,
      meanMs,
      minMs: totalValues.length ? Math.min(...totalValues) : null,
      maxMs: totalValues.length ? Math.max(...totalValues) : null,
      runs,
    };

    console.log('[benchmark-scenario] result', summary);
    console.log('[benchmark-scenario-json]', JSON.stringify(summary));
  } finally {
    await server.close();
  }
}

main().catch((error) => {
  console.error('[benchmark-scenario] fatal', error);
  process.exitCode = 1;
});

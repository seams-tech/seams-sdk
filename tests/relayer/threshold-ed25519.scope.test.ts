import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import * as ed from '@noble/ed25519';
import bs58 from 'bs58';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ActionType, type ActionArgsWasm } from '@/core/types/actions';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayPublishableKeyAuthAdapter,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  handle_signer_message,
  threshold_ed25519_compute_near_tx_signing_digests,
} from '../../wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm,
  deriveThresholdEd25519HssClientInputsWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
  type ThresholdEd25519HssClientRequestEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import {
  callCf,
  fetchJson,
  getPath,
  makeCfCtx,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';
import {
  createFixtureSigningRootShareResolverForUnitTests,
  deriveThresholdEd25519VerifyingShareForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';
import type {
  ThresholdEd25519AuthConsumeUsesResult,
  Ed25519AuthSessionRecord,
  Ed25519AuthSessionStatus,
  Ed25519AuthSessionStore,
} from '@server/core/ThresholdService/stores/AuthSessionStore';

type ThresholdEd25519AuthConsumeResult =
  | { ok: true; record: Ed25519AuthSessionRecord; remainingUses: number }
  | { ok: false; code: string; message: string };

const DEFAULT_HSS_PRF_FIRST_B64U = Buffer.from(new Uint8Array(32).fill(13)).toString('base64url');
const DEFAULT_HSS_SIGNING_ROOT_ID = 'org_threshold_scope_test';
const MANAGED_RUNTIME_ORG_ID = 'org_threshold_scope_test';
const MANAGED_RUNTIME_PROJECT_ID = 'proj_threshold_scope_test';
const MANAGED_RUNTIME_ENVIRONMENT_ID = `${MANAGED_RUNTIME_PROJECT_ID}:dev`;
const MANAGED_RUNTIME_ORIGIN = 'https://example.localhost';
const DEFAULT_HSS_KEY_PURPOSE = 'near-ed25519-signing';
const DEFAULT_HSS_DERIVATION_VERSION = 1;
const TEST_CLIENT_OUTPUT_MASK_B64U = Buffer.alloc(32, 0x5a).toString('base64url');
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
let hssClientSignerWasmInitializedForDirectWorkerTests = false;

type CapturedLogEntry = {
  level: 'debug' | 'info' | 'warn' | 'error';
  args: unknown[];
};

function makeCapturedLogger(): {
  logger: {
    debug: (...args: unknown[]) => void;
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
  };
  entries: CapturedLogEntry[];
} {
  const entries: CapturedLogEntry[] = [];
  return {
    logger: {
      debug: (...args: unknown[]) => {
        entries.push({ level: 'debug', args });
      },
      info: (...args: unknown[]) => {
        entries.push({ level: 'info', args });
      },
      warn: (...args: unknown[]) => {
        entries.push({ level: 'warn', args });
      },
      error: (...args: unknown[]) => {
        entries.push({ level: 'error', args });
      },
    },
    entries,
  };
}

function makeAuthServiceForThreshold(): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
};
function makeAuthServiceForThreshold(input: {
  logger?: {
    debug?: (...args: unknown[]) => void;
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    error?: (...args: unknown[]) => void;
  } | null;
}): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
};
function makeAuthServiceForThreshold(input?: {
  logger?: {
    debug?: (...args: unknown[]) => void;
    info?: (...args: unknown[]) => void;
    warn?: (...args: unknown[]) => void;
    error?: (...args: unknown[]) => void;
  } | null;
}): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const thresholdConfig = {
    THRESHOLD_NODE_ROLE: 'coordinator',
    ACCOUNT_ID_DERIVATION_SECRET: 'test-account-id-derivation-secret',
    signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests(),
  } as const;
  const logger = input?.logger ?? null;
  const svc = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    thresholdStore: thresholdConfig,
    logger,
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
    thresholdStore: thresholdConfig,
    logger,
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

function buildThresholdEcdsaSessionClaimsForEd25519Mint(input: {
  nearAccountId: string;
  rpId: string;
  sessionId: string;
  walletSigningSessionId: string;
}) {
  return {
    kind: 'threshold_ecdsa_session_v1',
    walletId: input.nearAccountId,
    sessionId: input.sessionId,
    walletSigningSessionId: input.walletSigningSessionId,
    subjectId: `${input.nearAccountId}:evm-family`,
    keyScope: 'evm-family',
    keyHandle: `${input.sessionId}:key-handle`,
    relayerKeyId: `${input.sessionId}:ecdsa-relayer-key`,
    rpId: input.rpId,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
  } as const;
}

async function createManagedRuntimeFixture() {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const ctx = {
    orgId: MANAGED_RUNTIME_ORG_ID,
    actorUserId: 'threshold-ed25519-scope-test',
    roles: ['admin'],
  };
  await orgProjectEnv.upsertOrganization(ctx, {
    name: 'Threshold Ed25519 Scope Test',
    slug: 'threshold-ed25519-scope-test',
  });
  await orgProjectEnv.createProject(ctx, {
    id: MANAGED_RUNTIME_PROJECT_ID,
    name: 'Threshold Ed25519 Scope Test Project',
    liveEnvironmentsEnabled: true,
  });
  await orgProjectEnv.updateEnvironment(ctx, MANAGED_RUNTIME_ENVIRONMENT_ID, {
    signingRootVersion: 'default',
  });
  const created = await apiKeys.createApiKey(ctx, {
    kind: 'publishable_key',
    name: 'threshold-ed25519-scope-test-browser',
    environmentId: MANAGED_RUNTIME_ENVIRONMENT_ID,
    allowedOrigins: [MANAGED_RUNTIME_ORIGIN],
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  return {
    orgProjectEnv,
    publishableKeyAuth: createRelayPublishableKeyAuthAdapter(apiKeys),
    publishableKey: created.secret,
    runtimeEnvironmentId: MANAGED_RUNTIME_ENVIRONMENT_ID,
    origin: MANAGED_RUNTIME_ORIGIN,
  };
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
  readonly consumedOnceKeys = new Map<string, Set<string>>();
  readonly replayGuards = new Set<string>();
  consumeUseCalls = 0;
  consumeUseCountCalls = 0;

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    this.records.set(id, record);
    this.uses.set(id, Math.max(0, Number(opts.remainingUses) || 0));
    this.consumedOnceKeys.set(id, new Set());
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    return this.records.get(id) ?? null;
  }

  async getSessionStatus(id: string): Promise<Ed25519AuthSessionStatus | null> {
    const record = await this.getSession(id);
    if (!record) return null;
    return {
      record,
      expiresAtMs: record.expiresAtMs,
      remainingUses: this.uses.get(id) ?? 0,
    };
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

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const consumeKey = String(idempotencyKey || '').trim();
    const consumed = this.consumedOnceKeys.get(id) || new Set<string>();
    if (consumeKey && consumed.has(consumeKey)) {
      return { ok: true, remainingUses: this.uses.get(id) ?? 0 };
    }
    const result = await this.consumeUseCount(id);
    if (result.ok && consumeKey) {
      consumed.add(consumeKey);
      this.consumedOnceKeys.set(id, consumed);
    }
    return result;
  }

  async hasConsumedUseCountOnce(id: string, idempotencyKey: string) {
    const consumeKey = String(idempotencyKey || '').trim();
    return {
      ok: true as const,
      consumed: !!consumeKey && !!this.consumedOnceKeys.get(id)?.has(consumeKey),
    };
  }

  async reserveReplayGuard(scopeId: string, replayKey: string) {
    const key = `${scopeId}:${replayKey}`;
    if (this.replayGuards.has(key)) {
      return { ok: false as const, code: 'export_nonce_replay', message: 'duplicate' };
    }
    this.replayGuards.add(key);
    return { ok: true as const };
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
  extraTxSigningRequests?: Array<{
    receiverId: string;
    actions: ActionArgsWasm[];
  }>;
}): Promise<{
  body: Record<string, unknown>;
  signingDigestB64u: string;
  signingDigestBytesList: Uint8Array[];
}> {
  const txSigningRequests = [
    {
      nearAccountId: input.nearAccountId,
      receiverId: input.receiverId,
      actions: input.actions,
    },
    ...(input.extraTxSigningRequests || []).map((tx) => ({
      nearAccountId: input.nearAccountId,
      receiverId: tx.receiverId,
      actions: tx.actions,
    })),
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
  const signingDigestBytesList = digestsUnknown.map((digest) =>
    digest instanceof Uint8Array ? digest : null,
  );
  const first = signingDigestBytesList[0];
  const signingDigestBytes = first instanceof Uint8Array ? first : null;
  if (!signingDigestBytes || signingDigestBytes.length !== 32) {
    throw new Error('Failed to compute near_tx signing digest via WASM');
  }
  for (const digest of signingDigestBytesList) {
    if (!(digest instanceof Uint8Array) || digest.length !== 32) {
      throw new Error('Failed to compute near_tx signing digest via WASM');
    }
  }

  return {
    signingDigestB64u: base64UrlEncode(signingDigestBytes),
    signingDigestBytesList: signingDigestBytesList as Uint8Array[],
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

async function invokeNearSignerWorkerDirect(request: {
  sessionId?: string;
  type: number;
  payload?: Record<string, unknown>;
}): Promise<any> {
  if (
    request.type === WorkerRequestType.DeriveThresholdEd25519HssClientInputs ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssSession ||
    request.type === WorkerRequestType.PrepareThresholdEd25519HssClientRequest ||
    request.type === WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask ||
    request.type === WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
  ) {
    if (!hssClientSignerWasmInitializedForDirectWorkerTests) {
      initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
      hssClientSignerWasmInitializedForDirectWorkerTests = true;
    }
    switch (request.type) {
      case WorkerRequestType.DeriveThresholdEd25519HssClientInputs:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess,
          payload: derive_threshold_ed25519_hss_client_inputs(request.payload || {}),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssSession:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess,
          payload: threshold_ed25519_hss_prepare_session(request.payload || {}),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssClientRequest:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess,
          payload: threshold_ed25519_hss_prepare_client_request(request.payload || {}),
        };
      case WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskSuccess,
          payload: threshold_ed25519_hss_derive_client_output_mask(request.payload || {}),
        };
      case WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
          payload: threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
            request.payload || {},
          ),
        };
      default:
        break;
    }
  }
  return handle_signer_message({
    type: request.type,
    payload: {
      sessionId: String(request.sessionId || '').trim(),
      ...(request.payload || {}),
    },
  });
}

const TEST_NEAR_SIGNER_WORKER_CTX = {
  requestWorkerOperation: async ({ request }: { request: any }) =>
    await invokeNearSignerWorkerDirect(request),
};

async function buildClientOwnedHssEvaluationResultForTest(args: {
  preparedSession: Record<string, unknown>;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  respondedJson: Record<string, unknown> | null | undefined;
}) {
  return await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm({
    preparedSession: {
      evaluatorDriverStateB64u: String(args.preparedSession.evaluatorDriverStateB64u || ''),
    },
    clientRequest: args.clientRequest,
    serverInputDelivery: {
      serverInputDeliveryB64u: String(args.respondedJson?.serverInputDeliveryB64u || ''),
    },
    clientOutputMaskB64u: TEST_CLIENT_OUTPUT_MASK_B64U,
    workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
  });
}

async function buildThresholdEd25519HssSessionMaterial(input: {
  thresholdSessionId: string;
  nearAccountId: string;
  keyVersion?: string;
  participantIds?: number[];
  signingRootId?: string;
  prfFirstB64u?: string;
}): Promise<{
  context: {
    signingRootId: string;
    nearAccountId: string;
    keyPurpose: string;
    keyVersion: string;
    participantIds: number[];
    derivationVersion: number;
  };
  clientInputs: Awaited<ReturnType<typeof deriveThresholdEd25519HssClientInputsWasm>>;
}> {
  const participantIds = Array.isArray(input.participantIds)
    ? input.participantIds.map((value) => Number(value))
    : [1, 2];
  const context = {
    signingRootId: String(input.signingRootId || DEFAULT_HSS_SIGNING_ROOT_ID).trim(),
    nearAccountId: String(input.nearAccountId || '').trim(),
    keyPurpose: DEFAULT_HSS_KEY_PURPOSE,
    keyVersion: String(input.keyVersion || THRESHOLD_ED25519_KEY_VERSION_V1).trim(),
    participantIds,
    derivationVersion: DEFAULT_HSS_DERIVATION_VERSION,
  };
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `${String(input.thresholdSessionId || '').trim()}:hss-client-inputs`,
    signingRootId: context.signingRootId,
    nearAccountId: context.nearAccountId,
    keyPurpose: context.keyPurpose,
    keyVersion: context.keyVersion,
    participantIds: context.participantIds,
    derivationVersion: context.derivationVersion,
    prfFirstB64u: String(input.prfFirstB64u || DEFAULT_HSS_PRF_FIRST_B64U).trim(),
    workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
  });
  return { context, clientInputs };
}

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
  test('session mint rejects same-account threshold-ecdsa session without WebAuthn', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
        service,
        threshold,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
      });
      const ecdsaJwt = await session.signJwt(
        'bob.testnet',
        buildThresholdEcdsaSessionClaimsForEd25519Mint({
          nearAccountId: 'bob.testnet',
          rpId: 'example.localhost',
          sessionId: 'ecdsa-session-for-ed25519-mint',
          walletSigningSessionId: 'wallet-signing-session-for-ed25519-mint',
        }),
      );
      const thresholdSessionBody = await buildThresholdSessionBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId: `ed25519-from-ecdsa-${Date.now()}`,
        ttlMs: 60_000,
        remainingUses: 2,
      });
      delete thresholdSessionBody.webauthn_authentication;

      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ecdsaJwt}`,
        },
        body: JSON.stringify(thresholdSessionBody),
      });

      expect(minted.status, minted.text).toBe(400);
      expect(minted.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
        message: 'webauthn_authentication is required for threshold-ed25519 session mint',
      });
    } finally {
      await srv.close();
    }
  });

  test('integration: session/exchange -> threshold session -> authorize -> sign/init', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    enableOidcExchangeForTest(service, 'bob.testnet');

    const { session } = createTestSessionAdapter();
    const managedRuntime = await createManagedRuntimeFixture();
    const router = createRelayRouter(service, {
      threshold,
      session,
      corsOrigins: [managedRuntime.origin],
      orgProjectEnv: managedRuntime.orgProjectEnv,
      publishableKeyAuth: managedRuntime.publishableKeyAuth,
    });
    const srv = await startExpressRouter(router);
    try {
      const exchanged = await fetchJson(`${srv.baseUrl}/session/exchange`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${managedRuntime.publishableKey}`,
          Origin: managedRuntime.origin,
        },
        body: JSON.stringify({
          sessionKind: 'jwt',
          runtimeEnvironmentId: managedRuntime.runtimeEnvironmentId,
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
      expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'projectId')).toBe(
        MANAGED_RUNTIME_PROJECT_ID,
      );
      expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'envId')).toBe('dev');
      expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'signingRootVersion')).toBe(
        'default',
      );

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
      const thresholdAuthToken = String(minted.json?.jwt || '');
      expect(thresholdAuthToken).toContain('testjwt-');

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
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${thresholdAuthToken}` },
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
          unlockBackend: 'passkey',
          userId: 'bob.testnet',
          rpId: 'example.localhost',
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
      const thresholdAuthToken = String(minted.json?.jwt || '');
      expect(thresholdAuthToken).toContain('testjwt-');

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
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${thresholdAuthToken}` },
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
      const wrongScopeMinted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          await buildThresholdSessionBody({
            relayerKeyId,
            clientVerifyingShareB64u,
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            sessionId: `${sessionId}-wrong-scope`,
            ttlMs: 60_000,
            remainingUses: 4,
          }),
        ),
      });
      expect(wrongScopeMinted.status).toBe(200);
      expect(wrongScopeMinted.json?.ok).toBe(true);
      const wrongScopeJwt = String(wrongScopeMinted.json?.jwt || '');
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

      const { body: secondAuthorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver-two.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
      });

      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(secondAuthorizeBody),
      });
      expect(auth2.status).toBe(401);
      expect(auth2.json?.code).toBe('unauthorized');
    } finally {
      await srv.close();
    }
  });

  test('threshold session: NEAR batch authorizations consume one wallet use', async () => {
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

      const sessionId = `sess-${Date.now()}-batch`;
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

      const batchAuthorize = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver-one.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
        extraTxSigningRequests: [
          {
            receiverId: 'receiver-two.testnet',
            actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
          },
        ],
      });
      expect(batchAuthorize.signingDigestBytesList).toHaveLength(2);

      const auth1 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(batchAuthorize.body),
      });
      expect(auth1.status, auth1.text).toBe(200);
      expect(auth1.json?.ok, auth1.text).toBe(true);

      const secondDigestBody = {
        ...batchAuthorize.body,
        signing_digest_32: Array.from(batchAuthorize.signingDigestBytesList[1]!),
      };
      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(secondDigestBody),
      });
      expect(auth2.status, auth2.text).toBe(200);
      expect(auth2.json?.ok, auth2.text).toBe(true);

      const { body: nextOperationBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver-three.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '3' }],
      });
      const auth3 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(nextOperationBody),
      });
      expect(auth3.status).toBe(401);
      expect(auth3.json?.code).toBe('unauthorized');
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

      const { body: secondAuthorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver-two.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
      });

      const auth2 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt2}` },
        body: JSON.stringify(secondAuthorizeBody),
      });
      expect(auth2.status).toBe(200);
      expect(auth2.json?.ok).toBe(true);

      // Third authorize should fail (2 uses total, even after replaying /session).
      const { body: thirdAuthorizeBody } = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver-three.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '3' }],
      });
      const auth3 = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt2}` },
        body: JSON.stringify(thirdAuthorizeBody),
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

  test('hss respond rejects legacy evaluator OT state on the server route', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
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
      expect(minted.status, minted.text).toBe(200);
      expect(minted.json?.ok, minted.text).toBe(true);
      const jwt = String(minted.json?.jwt || '');

      const { context } = await buildThresholdEd25519HssSessionMaterial({
        thresholdSessionId: sessionId,
        nearAccountId: 'bob.testnet',
      });
      const prepared = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          operation: 'tx_signing',
          context,
        }),
      });
      expect(prepared.status, prepared.text).toBe(200);
      expect(prepared.json?.ok, prepared.text).toBe(true);

      const responded = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: 'public-client-request-message',
            evaluatorOtStateB64u: 'legacy-client-local-state',
          },
        }),
      });
      expect(responded.status, responded.text).toBe(400);
      expect(responded.json?.code, responded.text).toBe('invalid_body');
      expect(String(responded.json?.message || ''), responded.text).toContain(
        'clientRequest.evaluatorOtStateB64u must stay outside the server-visible request',
      );
    } finally {
      await srv.close();
    }
  });

  test('hss finalize rejects relayer-share repair on wrong account scope', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
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
        remainingUses: 4,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');
      const wrongScopeMinted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          await buildThresholdSessionBody({
            relayerKeyId,
            clientVerifyingShareB64u,
            nearAccountId: 'alice.testnet',
            rpId: 'example.localhost',
            sessionId: `${sessionId}-wrong-scope`,
            ttlMs: 60_000,
            remainingUses: 4,
          }),
        ),
      });
      expect(wrongScopeMinted.status).toBe(200);
      expect(wrongScopeMinted.json?.ok).toBe(true);
      const wrongScopeJwt = String(wrongScopeMinted.json?.jwt || '');

      const { context, clientInputs } = await buildThresholdEd25519HssSessionMaterial({
        thresholdSessionId: sessionId,
        nearAccountId: 'bob.testnet',
      });
      await (threshold as any).keyStore.del(relayerKeyId);

      const prepared = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          operation: 'tx_signing',
          context,
        }),
      });
      expect(prepared.status, prepared.text).toBe(200);
      expect(prepared.json?.ok, prepared.text).toBe(true);
      const preparedSession = prepared.json?.preparedSession as any;
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: String(preparedSession?.evaluatorDriverStateB64u || ''),
        clientOtOfferMessageB64u: String(prepared.json?.clientOtOfferMessageB64u || ''),
        clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const responded = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        }),
      });
      expect(responded.status, responded.text).toBe(200);
      expect(responded.json?.ok, responded.text).toBe(true);

      const evaluationResult = await buildClientOwnedHssEvaluationResultForTest({
        preparedSession,
        clientRequest,
        respondedJson: responded.json,
      });

      const finalized = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${wrongScopeJwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          evaluationResult,
        }),
      });
      expect(finalized.status, finalized.text).toBe(401);
      expect(finalized.json?.code, finalized.text).toBe('unauthorized');
      expect(await (threshold as any).keyStore.get(relayerKeyId)).toBeNull();
    } finally {
      await srv.close();
    }
  });

  test('hss finalize rejects client-owned evaluation artifact with wrong staged binding', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
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
        remainingUses: 4,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');

      const { context, clientInputs } = await buildThresholdEd25519HssSessionMaterial({
        thresholdSessionId: sessionId,
        nearAccountId: 'bob.testnet',
      });
      await (threshold as any).keyStore.del(relayerKeyId);

      const prepared = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          operation: 'tx_signing',
          context,
        }),
      });
      expect(prepared.status, prepared.text).toBe(200);
      expect(prepared.json?.ok, prepared.text).toBe(true);
      const preparedSession = prepared.json?.preparedSession as any;
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: String(preparedSession?.evaluatorDriverStateB64u || ''),
        clientOtOfferMessageB64u: String(prepared.json?.clientOtOfferMessageB64u || ''),
        clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const responded = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        }),
      });
      expect(responded.status, responded.text).toBe(200);
      expect(responded.json?.ok, responded.text).toBe(true);

      const evaluationResult = await buildClientOwnedHssEvaluationResultForTest({
        preparedSession,
        clientRequest,
        respondedJson: responded.json,
      });

      const finalized = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          evaluationResult: {
            ...evaluationResult,
            contextBindingB64u: base64UrlEncode(randomBytes32()),
          },
        }),
      });
      expect(finalized.status, finalized.text).toBe(400);
      expect(finalized.json?.code, finalized.text).toBe('invalid_body');
      expect(String(finalized.json?.message || ''), finalized.text).toContain(
        'evaluationResult context binding mismatch',
      );
      expect(await (threshold as any).keyStore.get(relayerKeyId)).toBeNull();
    } finally {
      await srv.close();
    }
  });

  test('hss prepare/respond logs compact ceremony-state measurements', async () => {
    const captured = makeCapturedLogger();
    const { service, threshold } = makeAuthServiceForThreshold({ logger: captured.logger });
    const { session } = createTestSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);
    try {
      const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
      const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
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
        remainingUses: 4,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');

      const { context, clientInputs } = await buildThresholdEd25519HssSessionMaterial({
        thresholdSessionId: sessionId,
        nearAccountId: 'bob.testnet',
      });

      const prepared = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          operation: 'tx_signing',
          context,
        }),
      });
      expect(prepared.status, prepared.text).toBe(200);
      expect(prepared.json?.ok, prepared.text).toBe(true);

      const ceremonyHandle = String(prepared.json?.ceremonyHandle || '');
      const ceremonyStore = (threshold as any).ed25519HssCeremonyStore as Map<string, any>;
      const storedCeremony = ceremonyStore.get(ceremonyHandle) as Record<string, any> | undefined;
      expect(storedCeremony).toBeTruthy();
      expect(
        Object.prototype.hasOwnProperty.call(storedCeremony?.preparedSession || {}, 'orgId'),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          storedCeremony?.preparedSession || {},
          'nearAccountId',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          storedCeremony?.serverInputs || {},
          'contextBindingB64u',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          storedCeremony?.preparedServerSession || {},
          'contextBindingB64u',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(
          storedCeremony?.preparedServerSession || {},
          'clientOtOfferMessageB64u',
        ),
      ).toBe(false);
      expect(storedCeremony?.preparedServerSession?.evaluatorDriverStateBytes).toBeInstanceOf(
        Uint8Array,
      );
      expect(storedCeremony?.preparedServerSession?.garblerDriverStateBytes).toBeInstanceOf(
        Uint8Array,
      );
      expect(storedCeremony?.serverInputs?.yRelayerBytes).toBeInstanceOf(Uint8Array);
      expect(storedCeremony?.serverInputs?.tauRelayerBytes).toBeInstanceOf(Uint8Array);

      const preparedSession = prepared.json?.preparedSession as any;
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: String(preparedSession?.evaluatorDriverStateB64u || ''),
        clientOtOfferMessageB64u: String(prepared.json?.clientOtOfferMessageB64u || ''),
        clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const responded = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        }),
      });
      expect(responded.status, responded.text).toBe(200);
      expect(responded.json?.ok, responded.text).toBe(true);
      const storedCeremonyAfterRespond = ceremonyStore.get(ceremonyHandle) as
        | Record<string, any>
        | undefined;
      expect(storedCeremonyAfterRespond).toBeTruthy();
      expect(
        Object.prototype.hasOwnProperty.call(
          storedCeremonyAfterRespond || {},
          'contextBindingB64u',
        ),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(storedCeremonyAfterRespond || {}, 'serverInputs'),
      ).toBe(false);
      expect(
        Object.prototype.hasOwnProperty.call(storedCeremonyAfterRespond || {}, 'evaluationResult'),
      ).toBe(false);

      const prepareTimingEntry = captured.entries.find(
        (entry) =>
          entry.level === 'info' && entry.args[0] === '[threshold-ed25519] hss prepare timings',
      );
      expect(prepareTimingEntry).toBeTruthy();
      const prepareTiming = (prepareTimingEntry?.args[1] as Record<string, unknown>) || {};
      expect(prepareTiming).toHaveProperty('ceremonyStateBytes');
      expect(Number(prepareTiming.evaluatorDriverStateBytes || 0)).toBeGreaterThan(0);
      expect(Number(prepareTiming.evaluatorDriverStatePayloadBytes || 0)).toBeGreaterThan(0);
      expect(Number(prepareTiming.evaluatorDriverStateTransportOverheadBytes || 0)).toBeGreaterThan(
        0,
      );
      expect(Number(prepareTiming.clientOtOfferMessageBytes || 0)).toBeGreaterThan(0);
      expect(Number(prepareTiming.clientOtOfferMessagePayloadBytes || 0)).toBeGreaterThan(0);
      expect(Number(prepareTiming.clientOtOfferMessageTransportOverheadBytes || 0)).toBeGreaterThan(
        0,
      );
      expect(
        Number(
          (prepareTiming.ceremonyStateBytes as Record<string, unknown>)?.preparedSessionBytes || 0,
        ),
      ).toBeGreaterThan(0);
      expect(
        Number(
          (prepareTiming.ceremonyStateBytes as Record<string, unknown>)?.serverInputsBytes || 0,
        ),
      ).toBeGreaterThan(0);

      const respondTimingEntry = captured.entries.find(
        (entry) =>
          entry.level === 'info' && entry.args[0] === '[threshold-ed25519] hss respond timings',
      );
      expect(respondTimingEntry).toBeTruthy();
      const respondTiming = (respondTimingEntry?.args[1] as Record<string, unknown>) || {};
      expect(respondTiming).toHaveProperty('ceremonyStateBytes');
      expect(Number(respondTiming.clientRequestMessageBytes || 0)).toBeGreaterThan(0);
      expect(Number(respondTiming.clientRequestMessagePayloadBytes || 0)).toBeGreaterThan(0);
      expect(Number(respondTiming.clientRequestMessageTransportOverheadBytes || 0)).toBeGreaterThan(
        0,
      );
      expect(Number(respondTiming.serverInputDeliveryBytes || 0)).toBeGreaterThan(0);
      expect(Number(respondTiming.serverInputDeliveryPayloadBytes || 0)).toBeGreaterThan(0);
      expect(
        Number(respondTiming.serverInputDeliveryTransportOverheadBytes || 0),
      ).toBeGreaterThanOrEqual(0);
      expect(String(respondTiming.respondEngine || '')).toBe('wasm');
      if (respondTiming.respondEngine === 'wasm') {
        const breakdown = (respondTiming.wasmRespondBreakdownMs as Record<string, unknown>) || {};
        expect(Number(breakdown.decodeMessagesMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.materializeSessionMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.prepareDeliveryMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.encodeDeliveryMs || 0)).toBeGreaterThanOrEqual(0);
      }
      expect(
        Number(
          (respondTiming.ceremonyStateBytes as Record<string, unknown>)?.serverInputsBytes || 0,
        ),
      ).toBe(0);
      expect(
        Number(
          (respondTiming.ceremonyStateBytes as Record<string, unknown>)?.evaluationResultBytes || 0,
        ),
      ).toBe(0);
      expect(
        Number(
          (respondTiming.ceremonyStateBytes as Record<string, unknown>)
            ?.stagedEvaluatorArtifactBytes || 0,
        ),
      ).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('integration: sign-after-relayer-cache-loss repairs relayer share and succeeds on retry', async () => {
    const captured = makeCapturedLogger();
    const { service, threshold } = makeAuthServiceForThreshold({ logger: captured.logger });
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
        remainingUses: 6,
      });
      const minted = await fetchJson(`${srv.baseUrl}/threshold-ed25519/session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sessionBody),
      });
      expect(minted.status).toBe(200);
      expect(minted.json?.ok).toBe(true);
      const jwt = String(minted.json?.jwt || '');

      await (threshold as any).keyStore.del(relayerKeyId);
      expect(await (threshold as any).keyStore.get(relayerKeyId)).toBeNull();

      const firstAuthorize = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const firstAuth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(firstAuthorize.body),
      });
      expect(firstAuth.status, firstAuth.text).toBe(400);
      expect(firstAuth.json?.code, firstAuth.text).toBe('missing_key');

      const hssMaterial = await buildThresholdEd25519HssSessionMaterial({
        thresholdSessionId: sessionId,
        nearAccountId: 'bob.testnet',
      });
      const prepared = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          relayerKeyId,
          operation: 'tx_signing',
          context: hssMaterial.context,
        }),
      });
      expect(prepared.status, prepared.text).toBe(200);
      expect(prepared.json?.ok, prepared.text).toBe(true);
      const preparedSession = prepared.json?.preparedSession as any;
      const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
        evaluatorDriverStateB64u: String(preparedSession?.evaluatorDriverStateB64u || ''),
        clientOtOfferMessageB64u: String(prepared.json?.clientOtOfferMessageB64u || ''),
        clientInputs: hssMaterial.clientInputs,
        workerCtx: TEST_NEAR_SIGNER_WORKER_CTX,
      });
      const responded = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/respond`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
          },
        }),
      });
      expect(responded.status, responded.text).toBe(200);
      expect(responded.json?.ok, responded.text).toBe(true);

      const evaluationResult = await buildClientOwnedHssEvaluationResultForTest({
        preparedSession,
        clientRequest,
        respondedJson: responded.json,
      });

      const finalized = await fetchJson(`${srv.baseUrl}/threshold-ed25519/hss/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify({
          ceremonyHandle: prepared.json?.ceremonyHandle,
          evaluationResult,
        }),
      });
      expect(finalized.status, finalized.text).toBe(200);
      expect(finalized.json?.ok, finalized.text).toBe(true);

      const repairedKey = await (threshold as any).keyStore.get(relayerKeyId);
      expect(repairedKey).not.toBeNull();
      expect(String(repairedKey?.relayerSigningShareB64u || '')).not.toBe('');
      expect(String(repairedKey?.relayerVerifyingShareB64u || '')).not.toBe('');

      const secondAuthorize = await buildNearTxAuthorizeBody({
        relayerKeyId,
        clientVerifyingShareB64u,
        nearAccountId: 'bob.testnet',
        nearPublicKeyStr,
        receiverId: 'receiver.testnet',
        actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
      });
      const secondAuth = await fetchJson(`${srv.baseUrl}/threshold-ed25519/authorize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${jwt}` },
        body: JSON.stringify(secondAuthorize.body),
      });
      expect(secondAuth.status, secondAuth.text).toBe(200);
      expect(secondAuth.json?.ok, secondAuth.text).toBe(true);

      const secondInit = await fetchJson(`${srv.baseUrl}/threshold-ed25519/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId: String(secondAuth.json?.mpcSessionId || ''),
          relayerKeyId,
          nearAccountId: 'bob.testnet',
          signingDigestB64u: secondAuthorize.signingDigestB64u,
          clientCommitments: { hiding: 'a', binding: 'b' },
        }),
      });
      expect(secondInit.status, secondInit.text).toBe(200);
      expect(secondInit.json?.ok, secondInit.text).toBe(true);

      const cacheMissEntry = captured.entries.find(
        (entry) =>
          entry.level === 'warn' &&
          entry.args[0] === '[threshold-ed25519] relayer share cache miss',
      );
      expect(cacheMissEntry).toBeTruthy();

      const repairEntry = captured.entries.find(
        (entry) =>
          entry.level === 'warn' && entry.args[0] === '[threshold-ed25519] relayer share self-heal',
      );
      expect(repairEntry).toBeTruthy();
      expect((repairEntry?.args[1] as Record<string, unknown>)?.outcome).toBe('success');

      const finalizeTimingEntry = captured.entries.find(
        (entry) =>
          entry.level === 'info' && entry.args[0] === '[threshold-ed25519] hss finalize timings',
      );
      const respondTimingEntry = captured.entries.find(
        (entry) =>
          entry.level === 'info' && entry.args[0] === '[threshold-ed25519] hss respond timings',
      );
      expect(respondTimingEntry).toBeTruthy();
      const respondTiming = (respondTimingEntry?.args[1] as Record<string, unknown>) || {};
      expect(String(respondTiming.respondEngine || '')).toBe('wasm');
      expect(Number(respondTiming.clientRequestMessageBytes || 0)).toBeGreaterThan(0);
      expect(Number(respondTiming.serverInputDeliveryBytes || 0)).toBeGreaterThan(0);
      if (respondTiming.respondEngine === 'wasm') {
        const breakdown = (respondTiming.wasmRespondBreakdownMs as Record<string, unknown>) || {};
        expect(Number(breakdown.decodeMessagesMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.materializeSessionMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.prepareDeliveryMs || 0)).toBeGreaterThanOrEqual(0);
        expect(Number(breakdown.encodeDeliveryMs || 0)).toBeGreaterThanOrEqual(0);
      }
      expect(finalizeTimingEntry).toBeTruthy();
      expect((finalizeTimingEntry?.args[1] as Record<string, unknown>)?.relayerShareRepaired).toBe(
        true,
      );
      expect(
        Number(
          (finalizeTimingEntry?.args[1] as Record<string, unknown>)?.relayerShareRepairMs || 0,
        ),
      ).toBeGreaterThanOrEqual(0);
    } finally {
      await srv.close();
    }
  });
});

test.describe('threshold-ed25519 scope (cloudflare)', () => {
  test('session mint rejects same-account threshold-ecdsa session without WebAuthn', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const { session } = createTestSessionAdapter();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      threshold,
      session,
    });
    const { ctx } = makeCfCtx();

    const clientVerifyingShareB64u = await randomClientVerifyingShareB64u();
    const { relayerKeyId } = await provisionThresholdEd25519RegistrationMaterial({
      service,
      threshold,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
    });
    const ecdsaJwt = await session.signJwt(
      'bob.testnet',
      buildThresholdEcdsaSessionClaimsForEd25519Mint({
        nearAccountId: 'bob.testnet',
        rpId: 'example.localhost',
        sessionId: 'ecdsa-session-for-ed25519-mint',
        walletSigningSessionId: 'wallet-signing-session-for-ed25519-mint',
      }),
    );
    const thresholdSessionBody = await buildThresholdSessionBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      rpId: 'example.localhost',
      sessionId: `ed25519-from-ecdsa-cf-${Date.now()}`,
      ttlMs: 60_000,
      remainingUses: 2,
    });
    delete thresholdSessionBody.webauthn_authentication;

    const minted = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/session',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${ecdsaJwt}` },
      body: thresholdSessionBody,
      ctx,
    });

    expect(minted.status, minted.text).toBe(400);
    expect(minted.json).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'webauthn_authentication is required for threshold-ed25519 session mint',
    });
  });

  test('integration: session/exchange -> threshold session -> authorize -> sign/init', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    enableOidcExchangeForTest(service, 'bob.testnet');

    const { session } = createTestSessionAdapter();
    const managedRuntime = await createManagedRuntimeFixture();
    const handler = createCloudflareRouter(service, {
      corsOrigins: [managedRuntime.origin],
      threshold,
      session,
      orgProjectEnv: managedRuntime.orgProjectEnv,
      publishableKeyAuth: managedRuntime.publishableKeyAuth,
    });
    const { ctx } = makeCfCtx();

    const exchanged = await callCf(handler, {
      method: 'POST',
      path: '/session/exchange',
      origin: managedRuntime.origin,
      headers: { Authorization: `Bearer ${managedRuntime.publishableKey}` },
      body: {
        sessionKind: 'jwt',
        runtimeEnvironmentId: managedRuntime.runtimeEnvironmentId,
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
    expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'projectId')).toBe(
      MANAGED_RUNTIME_PROJECT_ID,
    );
    expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'envId')).toBe('dev');
    expect(getPath(state.json, 'claims', 'runtimePolicyScope', 'signingRootVersion')).toBe(
      'default',
    );

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
    const thresholdAuthToken = String(minted.json?.jwt || '');
    expect(thresholdAuthToken).toContain('testjwt-');

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
      headers: { Authorization: `Bearer ${thresholdAuthToken}` },
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
        unlockBackend: 'passkey',
        userId: 'bob.testnet',
        rpId: 'example.localhost',
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
    const thresholdAuthToken = String(minted.json?.jwt || '');
    expect(thresholdAuthToken).toContain('testjwt-');

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
      headers: { Authorization: `Bearer ${thresholdAuthToken}` },
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

    const { body: secondAuthorizeBody } = await buildNearTxAuthorizeBody({
      relayerKeyId,
      clientVerifyingShareB64u,
      nearAccountId: 'bob.testnet',
      nearPublicKeyStr,
      receiverId: 'receiver-two.testnet',
      actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
    });

    const auth2 = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/authorize',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${jwt}` },
      body: secondAuthorizeBody,
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

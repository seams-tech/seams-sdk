import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  RouterAbEcdsaDerivationPresignaturePoolPolicy,
  RouterAbEcdsaDerivationPresignaturePoolPolicyInput,
} from '@/core/types/seams';
import { DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY } from '@/core/config/defaultConfigs';
import {
  addSecp256k1PublicKeys33Wasm,
  validateSecp256k1PublicKey33Wasm,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33Wasm,
} from '../../chains/evm/evmCryptoWasm';
import type { EcdsaDerivationClientThresholdEcdsaPresignProgress as ThresholdEcdsaPresignProgressWasm } from '../../threshold/crypto/ecdsaDerivationClientWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  routerAbEcdsaDerivationPresignaturePoolFillInit,
  routerAbEcdsaDerivationPresignaturePoolFillStep,
  type RouterAbEcdsaDerivationPresignaturePoolFill,
} from './poolFillRoutes';
import type { RouterAbEcdsaDerivationPoolFillInitKeySelector } from './poolFillRoutes';
import {
  finalizeRouterAbEcdsaDerivationEvmDigestSigningV1,
  prepareRouterAbEcdsaDerivationEvmDigestSigningV1,
  type RouterAbWalletSessionCredential,
} from '../../../rpcClients/relayer/routerAbNormalSigning';
import {
  formatEcdsaKeyHandleForWire,
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaKeyHandle,
  type EcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';

export type RouterAbEcdsaDerivationClientPresignatureRefillInput = {
  relayerUrl: string;
  keyHandle?: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  thresholdEcdsaPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  credential: RouterAbWalletSessionCredential;
  routerAbEcdsaDerivationPoolFill: RouterAbEcdsaDerivationPresignaturePoolFill;
  workerCtx: WorkerOperationContext;
};

function recoverableSignatureErrorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || 'signature recovery failed',
  );
}

export type RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult = {
  scheduled: boolean;
  reason:
    | 'scheduled'
    | 'disabled'
    | 'cold_start_pool_empty'
    | 'depth_above_trigger'
    | 'depth_at_or_above_target'
    | 'in_flight_for_pool_key'
    | 'global_in_flight_limit'
    | 'invalid_args';
  depth: number;
  targetDepth: number;
};

export type RouterAbEcdsaDerivationClientSigningMaterialSource = {
  kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1';
  initClientPresignSession: (input: {
    sessionId: string;
    groupPublicKey33: Uint8Array;
    workerCtx: WorkerOperationContext;
  }) => Promise<ThresholdEcdsaPresignProgressWasm>;
  stepClientPresignSession: (input: {
    sessionId: string;
    stage: 'triples' | 'presign';
    incomingMessages: Uint8Array[];
    workerCtx: WorkerOperationContext;
  }) => Promise<ThresholdEcdsaPresignProgressWasm>;
  abortClientPresignSession: (input: {
    sessionId: string;
    workerCtx: WorkerOperationContext;
  }) => Promise<void>;
  computeSignatureShareFromPresignatureHandle: (input: {
    materialHandle: string;
    groupPublicKey33: Uint8Array;
    expectedPresignBigR33: Uint8Array;
    digest32: Uint8Array;
    entropy32: Uint8Array;
    workerCtx: WorkerOperationContext;
  }) => Promise<Uint8Array>;
};

type RouterAbEcdsaDerivationClientPresignatureRef = {
  presignatureId: string;
  bigRB64u: string;
  materialHandle: string;
  createdAtMs: number;
  expiresAtMs: number;
};

type RouterAbEcdsaDerivationCoordinatorError = {
  ok: false;
  code: string;
  message: string;
};

type RouterAbEcdsaDerivationCoordinatorOk = {
  ok: true;
  signature65: Uint8Array;
  signature65B64u: string;
  rB64u: string;
  sB64u: string;
  recId: number;
};

export type RouterAbEcdsaDerivationCoordinatorResult =
  | RouterAbEcdsaDerivationCoordinatorOk
  | RouterAbEcdsaDerivationCoordinatorError;

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function zeroizeRouterAbEcdsaDerivationClientPresignatureList(
  presignatures?: RouterAbEcdsaDerivationClientPresignatureRef[] | null,
): void {
  if (!Array.isArray(presignatures)) return;
}

function assertRouterAbEcdsaDerivationClientSigningMaterialSource(
  source: RouterAbEcdsaDerivationClientSigningMaterialSource,
): void {
  if (source?.kind !== 'router_ab_ecdsa_derivation_client_signing_material_source_v1') {
    throw new Error('Router A/B ECDSA derivation client signing material source is required');
  }
}

const MAX_HANDSHAKE_STEPS = 64;
const FIXED_ECDSA_PRESIGN_PROTOCOL_ID = 'seams/router-ab-ecdsa-presign/fixed-2of2/v1';
const ROUTER_AB_ECDSA_DERIVATION_SIGNING_TTL_MS = 60_000;
const ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_EXPIRY_SKEW_MS = 2_000;
const PRESIGN_REFILL_AUTHORITY_LOCK_PREFIX = 'w3a:router-ab-ecdsa-derivation:presignature-refill:';
const clientPresignaturePool = new Map<string, RouterAbEcdsaDerivationClientPresignatureRef[]>();
const clientPresignatureRefillInFlightByPoolKey = new Map<string, Promise<void>>();
const foregroundSignInFlightByPoolKey = new Map<string, number>();
const clientPresignaturePoolGenerationByPoolKey = new Map<string, number>();

type PresignProtocolStage = ThresholdEcdsaPresignProgressWasm['stage'];

function triplesAreComplete(stage: PresignProtocolStage): boolean {
  return stage === 'triples_done' || stage === 'presign' || stage === 'done';
}

function resolvePresignExchangeStage(input: {
  readonly clientStage: PresignProtocolStage;
  readonly serverStage: PresignProtocolStage;
}): 'triples' | 'presign' {
  return triplesAreComplete(input.clientStage) && triplesAreComplete(input.serverStage)
    ? 'presign'
    : 'triples';
}

type NavigatorLocksLike = {
  request: <T>(
    name: string,
    options: { mode?: 'exclusive' | 'shared'; ifAvailable?: boolean },
    callback: (lock: unknown) => Promise<T> | T,
  ) => Promise<T>;
};

function normalizeIntInRange(value: unknown, fallback: number, min: number, max: number): number {
  const n = Math.floor(Number(value));
  if (!Number.isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function normalizePresignPoolTargetDepth(value: unknown, fallback: number): number {
  return normalizeIntInRange(value, fallback, 1, 64);
}

function normalizePresignPoolLowWatermark(
  value: unknown,
  fallback: number,
  targetDepth: number,
): number {
  return normalizeIntInRange(value, fallback, 0, targetDepth);
}

export function resolveRouterAbEcdsaDerivationPresignaturePoolPolicy(
  input?:
    | RouterAbEcdsaDerivationPresignaturePoolPolicyInput
    | RouterAbEcdsaDerivationPresignaturePoolPolicy,
): RouterAbEcdsaDerivationPresignaturePoolPolicy {
  const source = input || DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY;
  const targetDepth = normalizePresignPoolTargetDepth(
    source.targetDepth,
    DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY.targetDepth,
  );
  const lowWatermark = normalizePresignPoolLowWatermark(
    source.lowWatermark,
    DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY.lowWatermark,
    targetDepth,
  );
  return {
    enabled:
      typeof source.enabled === 'boolean'
        ? source.enabled
        : DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY.enabled,
    targetDepth,
    lowWatermark,
    maxRefillInFlight: normalizeIntInRange(
      source.maxRefillInFlight,
      DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY.maxRefillInFlight,
      1,
      8,
    ),
    refillAttemptTimeoutMs: normalizeIntInRange(
      source.refillAttemptTimeoutMs,
      DEFAULT_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_POLICY.refillAttemptTimeoutMs,
      5_000,
      120_000,
    ),
  };
}

function makePresignaturePoolKey(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
}): string {
  const relayerUrl = String(args.relayerUrl || '')
    .trim()
    .replace(/\/+$/g, '');
  const parsedScope = parseRouterAbEcdsaDerivationNormalSigningScopeV1(args.scope);
  const scopeIdentityB64u = base64UrlEncode(
    routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1(parsedScope),
  );
  return [
    FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
    relayerUrl,
    scopeIdentityB64u,
  ].join('|');
}

async function runAsCrossRuntimeRefillAuthority(input: {
  poolKey: string;
  task: () => Promise<void>;
}): Promise<'acquired' | 'not_available'> {
  const navigatorObj = (globalThis as unknown as { navigator?: { locks?: NavigatorLocksLike } })
    .navigator;
  const locks = navigatorObj?.locks;
  if (!locks || typeof locks.request !== 'function') {
    await input.task();
    return 'acquired';
  }
  let acquired = false;
  await locks.request(
    `${PRESIGN_REFILL_AUTHORITY_LOCK_PREFIX}${input.poolKey}`,
    { mode: 'exclusive', ifAvailable: true },
    async (lock) => {
      if (!lock) return;
      acquired = true;
      await input.task();
    },
  );
  return acquired ? 'acquired' : 'not_available';
}

function popClientPresignature(
  poolKey: string,
): RouterAbEcdsaDerivationClientPresignatureRef | null {
  const list = pruneClientPresignaturePool(poolKey);
  if (!list || list.length === 0) return null;
  const item = list.shift() || null;
  if (!list.length) {
    clientPresignaturePool.delete(poolKey);
  } else {
    clientPresignaturePool.set(poolKey, list);
  }
  return item;
}

function pushClientPresignature(
  poolKey: string,
  item: RouterAbEcdsaDerivationClientPresignatureRef,
): void {
  if (!isClientPresignatureUsable(item)) return;
  const list = clientPresignaturePool.get(poolKey) || [];
  list.push(item);
  clientPresignaturePool.set(poolKey, list);
}

function getClientPresignaturePoolDepth(poolKey: string): number {
  return pruneClientPresignaturePool(poolKey)?.length || 0;
}

function isClientPresignatureUsable(
  item: RouterAbEcdsaDerivationClientPresignatureRef,
  nowMs = Date.now(),
): boolean {
  const expiresAtMs = Math.floor(Number(item.expiresAtMs));
  return (
    Boolean(item.presignatureId && item.bigRB64u && item.materialHandle) &&
    Number.isSafeInteger(expiresAtMs) &&
    expiresAtMs > nowMs + ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_EXPIRY_SKEW_MS
  );
}

function pruneClientPresignaturePool(
  poolKey: string,
  nowMs = Date.now(),
): RouterAbEcdsaDerivationClientPresignatureRef[] | null {
  const list = clientPresignaturePool.get(poolKey);
  if (!list || list.length === 0) {
    clientPresignaturePool.delete(poolKey);
    return null;
  }
  const live = list.filter((item) => isClientPresignatureUsable(item, nowMs));
  if (live.length === list.length) return list;
  if (live.length === 0) {
    clientPresignaturePool.delete(poolKey);
    return null;
  }
  clientPresignaturePool.set(poolKey, live);
  return live;
}

function getClientPresignaturePoolGeneration(poolKey: string): number {
  return clientPresignaturePoolGenerationByPoolKey.get(poolKey) || 0;
}

function bumpClientPresignaturePoolGeneration(poolKey: string): number {
  const nextGeneration = getClientPresignaturePoolGeneration(poolKey) + 1;
  clientPresignaturePoolGenerationByPoolKey.set(poolKey, nextGeneration);
  return nextGeneration;
}

function getForegroundSignInFlightCount(poolKey: string): number {
  return foregroundSignInFlightByPoolKey.get(poolKey) || 0;
}

function startForegroundSign(poolKey: string): void {
  const current = getForegroundSignInFlightCount(poolKey);
  foregroundSignInFlightByPoolKey.set(poolKey, current + 1);
}

function finishForegroundSign(poolKey: string): void {
  const current = getForegroundSignInFlightCount(poolKey);
  if (current <= 1) {
    foregroundSignInFlightByPoolKey.delete(poolKey);
    return;
  }
  foregroundSignInFlightByPoolKey.set(poolKey, current - 1);
}

async function waitForInFlightRefill(poolKey: string): Promise<void> {
  const inFlight = clientPresignatureRefillInFlightByPoolKey.get(poolKey);
  if (!inFlight) return;
  await inFlight.catch(() => {});
}

export function clearAllRouterAbEcdsaDerivationClientPresignatures(): void {
  zeroizeRouterAbEcdsaDerivationClientPresignatureList(
    Array.from(clientPresignaturePool.values()).flat(),
  );
  clientPresignaturePool.clear();
  clientPresignatureRefillInFlightByPoolKey.clear();
  foregroundSignInFlightByPoolKey.clear();
  clientPresignaturePoolGenerationByPoolKey.clear();
}

export function clearRouterAbEcdsaDerivationClientPresignaturesForLane(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
}): void {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
  });
  bumpClientPresignaturePoolGeneration(poolKey);
  zeroizeRouterAbEcdsaDerivationClientPresignatureList(clientPresignaturePool.get(poolKey));
  clientPresignaturePool.delete(poolKey);
  clientPresignatureRefillInFlightByPoolKey.delete(poolKey);
}

export function getRouterAbEcdsaDerivationClientPresignaturePoolDepth(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
}): number {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
  });
  return getClientPresignaturePoolDepth(poolKey);
}

export function scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill(
  args: RouterAbEcdsaDerivationClientPresignatureRefillInput & {
    poolPolicy?:
      | RouterAbEcdsaDerivationPresignaturePoolPolicyInput
      | RouterAbEcdsaDerivationPresignaturePoolPolicy;
    targetDepth?: number;
    triggerIfDepthAtOrBelow?: number;
  },
): RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult {
  const finalizeUnschedule = (
    reason: RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult['reason'],
    depth: number,
    targetDepth: number,
  ): RouterAbEcdsaDerivationClientPresignatureRefillScheduleResult => {
    return { scheduled: false, reason, depth, targetDepth };
  };
  try {
    const policy = resolveRouterAbEcdsaDerivationPresignaturePoolPolicy(args.poolPolicy);
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      scope: args.routerAbEcdsaDerivationPoolFill.scope,
    });
    const targetDepth = normalizePresignPoolTargetDepth(args.targetDepth, policy.targetDepth);
    const triggerDepth = normalizePresignPoolLowWatermark(
      args.triggerIfDepthAtOrBelow,
      policy.lowWatermark,
      targetDepth,
    );
    const depth = getClientPresignaturePoolDepth(poolKey);
    const scheduledGeneration = getClientPresignaturePoolGeneration(poolKey);

    if (!policy.enabled) {
      return finalizeUnschedule('disabled', depth, targetDepth);
    }
    if (depth > triggerDepth) {
      return finalizeUnschedule('depth_above_trigger', depth, targetDepth);
    }
    if (depth >= targetDepth) {
      return finalizeUnschedule('depth_at_or_above_target', depth, targetDepth);
    }
    if (clientPresignatureRefillInFlightByPoolKey.has(poolKey)) {
      return finalizeUnschedule('in_flight_for_pool_key', depth, targetDepth);
    }
    if (getForegroundSignInFlightCount(poolKey) > 0) {
      return finalizeUnschedule('in_flight_for_pool_key', depth, targetDepth);
    }
    if (clientPresignatureRefillInFlightByPoolKey.size >= policy.maxRefillInFlight) {
      return finalizeUnschedule('global_in_flight_limit', depth, targetDepth);
    }

    const refillInput: RouterAbEcdsaDerivationClientPresignatureRefillInput = {
      relayerUrl: args.relayerUrl,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      clientSigningMaterial: args.clientSigningMaterial,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      credential: args.credential,
      routerAbEcdsaDerivationPoolFill: args.routerAbEcdsaDerivationPoolFill,
      workerCtx: args.workerCtx,
    };
    const deadlineAtMs = Date.now() + policy.refillAttemptTimeoutMs;
    const refillTask = (async (): Promise<void> => {
      const authority = await runAsCrossRuntimeRefillAuthority({
        poolKey,
        task: async () => {
          while (Date.now() < deadlineAtMs) {
            if (getClientPresignaturePoolGeneration(poolKey) !== scheduledGeneration) return;
            const currentDepth = getClientPresignaturePoolDepth(poolKey);
            if (currentDepth >= targetDepth) return;
            const refill = await refillRouterAbEcdsaDerivationClientPresignaturePool({
              ...refillInput,
            });
            if (!refill.ok) return;
          }
        },
      });
      if (authority !== 'acquired') return;
    })()
      .catch(() => {})
      .finally(() => {
        const inFlight = clientPresignatureRefillInFlightByPoolKey.get(poolKey);
        if (inFlight === refillTask) {
          clientPresignatureRefillInFlightByPoolKey.delete(poolKey);
        }
      });
    clientPresignatureRefillInFlightByPoolKey.set(poolKey, refillTask);
    return { scheduled: true, reason: 'scheduled', depth, targetDepth };
  } catch {
    return { scheduled: false, reason: 'invalid_args', depth: 0, targetDepth: 0 };
  }
}

function toB64uMessages(messages: Uint8Array[]): string[] {
  return messages.map((entry) => base64UrlEncode(entry));
}

function fromB64uMessages(messagesB64u: string[] | undefined): Uint8Array[] {
  if (!Array.isArray(messagesB64u)) return [];
  return messagesB64u
    .map((entry) => String(entry || '').trim())
    .filter((entry) => Boolean(entry))
    .map((entry) => base64UrlDecode(entry));
}

async function resolveGroupPublicKey33(args: {
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const thresholdEcdsaPublicKeyB64u = String(args.thresholdEcdsaPublicKeyB64u || '').trim();
  if (thresholdEcdsaPublicKeyB64u) {
    const bytes = base64UrlDecode(thresholdEcdsaPublicKeyB64u);
    if (bytes.length !== 33) throw new Error('thresholdEcdsaPublicKeyB64u must decode to 33 bytes');
    return await validateSecp256k1PublicKey33Wasm({
      publicKey33: bytes,
      workerCtx: args.workerCtx,
    });
  }

  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const relayerVerifyingShareB64u = String(args.relayerVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u || !relayerVerifyingShareB64u) {
    throw new Error(
      'Missing thresholdEcdsaPublicKeyB64u (or relayerVerifyingShareB64u fallback) for Router A/B ECDSA derivation signing',
    );
  }

  const clientBytes = base64UrlDecode(clientVerifyingShareB64u);
  const relayerBytes = base64UrlDecode(relayerVerifyingShareB64u);
  if (clientBytes.length !== 33)
    throw new Error('clientVerifyingShareB64u must decode to 33 bytes');
  if (relayerBytes.length !== 33)
    throw new Error('relayerVerifyingShareB64u must decode to 33 bytes');
  const validatedClientPublicKey33 = await validateSecp256k1PublicKey33Wasm({
    publicKey33: clientBytes,
    workerCtx: args.workerCtx,
  });
  const validatedRelayerPublicKey33 = await validateSecp256k1PublicKey33Wasm({
    publicKey33: relayerBytes,
    workerCtx: args.workerCtx,
  });
  return await addSecp256k1PublicKeys33Wasm({
    left33: validatedClientPublicKey33,
    right33: validatedRelayerPublicKey33,
    workerCtx: args.workerCtx,
  });
}

async function runPresignHandshake(args: {
  relayerUrl: string;
  poolFillInitKeySelector: RouterAbEcdsaDerivationPoolFillInitKeySelector;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  groupPublicKey33: Uint8Array;
  credential: RouterAbWalletSessionCredential;
  requestTag?: string;
  routerAbEcdsaDerivationPoolFill: RouterAbEcdsaDerivationPresignaturePoolFill;
  workerCtx: WorkerOperationContext;
}): Promise<
  | { ok: true; presignature: RouterAbEcdsaDerivationClientPresignatureRef }
  | RouterAbEcdsaDerivationCoordinatorError
> {
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const result = await runPresignHandshakeAttempt(args);
    if (result.ok || !isRetryablePoolFillStale(result) || attempt === 1) return result;
  }
  return {
    ok: false,
    code: 'stale_session_state',
    message: 'Router A/B ECDSA derivation pool-fill session stayed stale after retry',
  };
}

async function runPresignHandshakeAttempt(args: {
  relayerUrl: string;
  poolFillInitKeySelector: RouterAbEcdsaDerivationPoolFillInitKeySelector;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  groupPublicKey33: Uint8Array;
  credential: RouterAbWalletSessionCredential;
  requestTag?: string;
  routerAbEcdsaDerivationPoolFill: RouterAbEcdsaDerivationPresignaturePoolFill;
  workerCtx: WorkerOperationContext;
}): Promise<
  | { ok: true; presignature: RouterAbEcdsaDerivationClientPresignatureRef }
  | RouterAbEcdsaDerivationCoordinatorError
> {
  assertRouterAbEcdsaDerivationClientSigningMaterialSource(args.clientSigningMaterial);
  const init = await routerAbEcdsaDerivationPresignaturePoolFillInit({
    relayerUrl: args.relayerUrl,
    ...args.poolFillInitKeySelector,
    count: 1,
    walletSessionJwt: args.credential.walletSessionJwt,
    requestTag: args.requestTag,
    poolFill: args.routerAbEcdsaDerivationPoolFill,
  });
  if (!init.ok) {
    return {
      ok: false,
      code: init.code || 'presign_init_failed',
      message: init.message || 'Router A/B ECDSA derivation pool-fill init failed',
    };
  }

  const presignSessionId = String(init.presignSessionId || '').trim();
  if (!presignSessionId) {
    return {
      ok: false,
      code: 'internal',
      message: 'Router A/B ECDSA derivation pool-fill init returned empty presignSessionId',
    };
  }

  const localSessionId = presignSessionId;

  let localPresignatureHandle: string | null = null;
  let localBigR33: Uint8Array | null = null;
  let serverPresignatureId: string | null = null;
  let serverBigRB64u: string | null = null;
  let serverDone = false;
  let clientStage: PresignProtocolStage = 'triples';
  let serverStage: PresignProtocolStage = init.stage || 'triples';
  let pendingClientOutgoing = [] as Uint8Array[];
  let pendingServerOutgoing = fromB64uMessages(init.outgoingMessagesB64u);
  let shouldAbortLocalSession = true;

  try {
    const localInit = await args.clientSigningMaterial.initClientPresignSession({
      sessionId: localSessionId,
      groupPublicKey33: args.groupPublicKey33,
      workerCtx: args.workerCtx,
    });
    clientStage = localInit.stage;
    pendingClientOutgoing = [...localInit.outgoingMessages];
    if (localInit.presignatureHandle && localInit.presignatureBigR33) {
      localPresignatureHandle = localInit.presignatureHandle;
      localBigR33 = localInit.presignatureBigR33;
    }

    for (let i = 0; i < MAX_HANDSHAKE_STEPS; i++) {
      if (pendingServerOutgoing.length > 0 && !localPresignatureHandle) {
        const localStepped = await args.clientSigningMaterial.stepClientPresignSession({
          sessionId: localSessionId,
          stage: resolvePresignExchangeStage({ clientStage, serverStage }),
          incomingMessages: pendingServerOutgoing,
          workerCtx: args.workerCtx,
        });
        clientStage = localStepped.stage;
        pendingServerOutgoing = [];
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.presignatureHandle && localStepped.presignatureBigR33) {
          localPresignatureHandle = localStepped.presignatureHandle;
          localBigR33 = localStepped.presignatureBigR33;
        }
      }

      if (!serverDone) {
        const stepArgs = {
          relayerUrl: args.relayerUrl,
          presignSessionId,
          stage: resolvePresignExchangeStage({ clientStage, serverStage }),
          outgoingMessagesB64u: toB64uMessages(pendingClientOutgoing),
          walletSessionJwt: args.credential.walletSessionJwt,
          requestTag: args.requestTag,
        } as const;
        const stepped = await routerAbEcdsaDerivationPresignaturePoolFillStep(stepArgs);
        pendingClientOutgoing = [];
        if (!stepped.ok) {
          return {
            ok: false,
            code: stepped.code || 'presign_step_failed',
            message: stepped.message || 'Router A/B ECDSA derivation pool-fill step failed',
          };
        }
        pendingServerOutgoing = fromB64uMessages(stepped.outgoingMessagesB64u);
        serverStage = stepped.stage || serverStage;
        if (stepped.event === 'presign_done') {
          serverPresignatureId = String(stepped.presignatureId || '').trim() || null;
          serverBigRB64u = String(stepped.bigRB64u || '').trim() || null;
          serverDone = true;
        }
      }

      if (localPresignatureHandle && localBigR33 && serverPresignatureId && serverBigRB64u) {
        break;
      }

      if (
        !pendingServerOutgoing.length &&
        !pendingClientOutgoing.length &&
        !localPresignatureHandle
      ) {
        const localStepped = await args.clientSigningMaterial.stepClientPresignSession({
          sessionId: localSessionId,
          stage: resolvePresignExchangeStage({ clientStage, serverStage }),
          incomingMessages: [],
          workerCtx: args.workerCtx,
        });
        clientStage = localStepped.stage;
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.presignatureHandle && localStepped.presignatureBigR33) {
          localPresignatureHandle = localStepped.presignatureHandle;
          localBigR33 = localStepped.presignatureBigR33;
        }
      }
    }

    if (!localPresignatureHandle || !localBigR33) {
      return {
        ok: false,
        code: 'presign_timeout',
        message: 'Client presign session did not reach done state',
      };
    }
    if (!serverPresignatureId || !serverBigRB64u) {
      return {
        ok: false,
        code: 'presign_timeout',
        message: 'Server presign session did not reach done state',
      };
    }
    if (localBigR33.length !== 33) {
      return {
        ok: false,
        code: 'internal',
        message: `Invalid local presignature bigR bytes (expected 33, got ${localBigR33.length})`,
      };
    }

    try {
      const createdAtMs = Date.now();
      const localBigRB64u = base64UrlEncode(localBigR33);
      if (localBigRB64u !== serverBigRB64u) {
        return {
          ok: false,
          code: 'presign_mismatch',
          message: 'Client/server presignature mismatch (bigR mismatch)',
        };
      }

      shouldAbortLocalSession = false;
      return {
        ok: true,
        presignature: {
          presignatureId: serverPresignatureId,
          bigRB64u: localBigRB64u,
          materialHandle: localPresignatureHandle,
          createdAtMs,
          expiresAtMs: clientPresignatureExpiresAtMs(args.routerAbEcdsaDerivationPoolFill),
        },
      };
    } finally {
      zeroizeBytes(localBigR33);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Router A/B ECDSA derivation pool-fill handshake failed',
    );
    return { ok: false, code: 'presign_failed', message: msg };
  } finally {
    zeroizeBytes(localBigR33);
    if (shouldAbortLocalSession) {
      await args.clientSigningMaterial
        .abortClientPresignSession({
          sessionId: localSessionId,
          workerCtx: args.workerCtx,
        })
        .catch(() => {});
    }
  }
}

function isRetryablePoolFillStale(result: RouterAbEcdsaDerivationCoordinatorError): boolean {
  return result.code === 'stale_session_state' || result.code === 'stale_pool_fill_session';
}

function routerAbEcdsaDerivationSigningIdentityFromScope(
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
): {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  thresholdEcdsaPublicKeyB64u: string;
} {
  const parsed = parseRouterAbEcdsaDerivationNormalSigningScopeV1(scope);
  return {
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(parsed.ecdsa_threshold_key_id),
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
      parsed.public_identity.derivation_client_share_public_key33_b64u,
    ),
    thresholdEcdsaPublicKeyB64u: parsed.public_identity.threshold_public_key33_b64u,
  };
}

function clientPresignatureExpiresAtMs(
  poolFill: RouterAbEcdsaDerivationPresignaturePoolFill,
): number {
  return Math.floor(Number(poolFill.expiresAtMs));
}

function isExpiredRouterAbEcdsaDerivationPresignatureError(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes('expiredlocalrequest') && normalized.includes('presignature pool');
}

function resolveRouterAbEcdsaDerivationPoolFillInitKeySelector(args: {
  keyHandle?: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
}):
  | { ok: true; value: RouterAbEcdsaDerivationPoolFillInitKeySelector }
  | { ok: false; code: 'invalid_args'; message: string } {
  if (args.keyHandle) {
    const keyHandle = formatEcdsaKeyHandleForWire(args.keyHandle);
    return { ok: true, value: { keyHandle } };
  }
  return {
    ok: false,
    code: 'invalid_args',
    message: 'Missing keyHandle for Router A/B ECDSA derivation pool-fill init selector',
  };
}

export async function signRouterAbEcdsaDerivationDigestWithPoolHit(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  credential: RouterAbWalletSessionCredential;
  signingDigest32: Uint8Array;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  expiresAtMs?: number;
  workerCtx: WorkerOperationContext;
}): Promise<RouterAbEcdsaDerivationCoordinatorResult> {
  let poolKey: string | null = null;
  let foregroundStarted = false;
  let presignature: RouterAbEcdsaDerivationClientPresignatureRef | null = null;
  let clientSignatureShare32: Uint8Array | null = null;
  try {
    const relayerUrl = String(args.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    if (!relayerUrl) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing relayerUrl for Router A/B ECDSA derivation signing',
      };
    }
    const signingIdentity = routerAbEcdsaDerivationSigningIdentityFromScope(args.scope);
    const ecdsaThresholdKeyId = signingIdentity.ecdsaThresholdKeyId;
    if (!ecdsaThresholdKeyId) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing ecdsaThresholdKeyId for Router A/B ECDSA derivation signing',
      };
    }
    const clientVerifyingShareB64u = signingIdentity.clientVerifyingShareB64u;
    if (!clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing clientVerifyingShareB64u for Router A/B ECDSA derivation signing',
      };
    }
    if (!(args.signingDigest32 instanceof Uint8Array) || args.signingDigest32.length !== 32) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'signingDigest32 must be 32 bytes for Router A/B ECDSA derivation signing',
      };
    }
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: signingIdentity.thresholdEcdsaPublicKeyB64u,
      workerCtx: args.workerCtx,
    });

    poolKey = makePresignaturePoolKey({
      relayerUrl,
      scope: args.scope,
    });
    startForegroundSign(poolKey);
    foregroundStarted = true;

    presignature = popClientPresignature(poolKey);
    if (!presignature) {
      await waitForInFlightRefill(poolKey);
      presignature = popClientPresignature(poolKey);
    }
    if (!presignature) {
      return {
        ok: false,
        code: 'pool_empty',
        message: 'Router A/B ECDSA derivation client presignature pool is empty',
      };
    }

    const expiresAtMs =
      Number.isSafeInteger(args.expiresAtMs) && Number(args.expiresAtMs) > Date.now()
        ? Math.floor(Number(args.expiresAtMs))
        : Date.now() + ROUTER_AB_ECDSA_DERIVATION_SIGNING_TTL_MS;
    const prepareRequest = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope: args.scope,
      requestId: secureRandomId(
        'router-ab-ecdsa-sign',
        32,
        'Router A/B ECDSA derivation sign request',
      ),
      clientPresignatureId: presignature.presignatureId,
      expiresAtMs,
      signingDigest32: args.signingDigest32,
    });
    const prepareResponse = await prepareRouterAbEcdsaDerivationEvmDigestSigningV1({
      relayServerUrl: relayerUrl,
      credential: args.credential,
      request: prepareRequest,
    });
    if (prepareResponse.server_big_r33_b64u !== presignature.bigRB64u) {
      return {
        ok: false,
        code: 'presign_mismatch',
        message: 'Router A/B ECDSA derivation SigningWorker returned a different presignature bigR',
      };
    }

    const bigR33 = base64UrlDecode(presignature.bigRB64u);
    const entropy32 = base64UrlDecode(prepareResponse.rerandomization_entropy32_b64u);
    try {
      if (bigR33.length !== 33) {
        return {
          ok: false,
          code: 'internal',
          message: 'Router A/B ECDSA derivation presign bigR must decode to 33 bytes',
        };
      }
      if (entropy32.length !== 32) {
        return {
          ok: false,
          code: 'internal',
          message: 'Router A/B ECDSA derivation rerandomization entropy must decode to 32 bytes',
        };
      }

      clientSignatureShare32 =
        await args.clientSigningMaterial.computeSignatureShareFromPresignatureHandle({
          materialHandle: presignature.materialHandle,
          groupPublicKey33,
          expectedPresignBigR33: bigR33,
          digest32: args.signingDigest32,
          entropy32,
          workerCtx: args.workerCtx,
        });
    } finally {
      zeroizeBytes(bigR33);
      zeroizeBytes(entropy32);
    }

    if (clientSignatureShare32.length !== 32) {
      return {
        ok: false,
        code: 'internal',
        message: `Invalid Router A/B ECDSA derivation client signature share length (expected 32, got ${clientSignatureShare32.length})`,
      };
    }

    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
      scope: args.scope,
      requestId: prepareRequest.request_id,
      budgetReservationId: prepareResponse.budget_reservation_id,
      budgetOperationId: prepareResponse.budget_operation_id,
      expiresAtMs: prepareRequest.expires_at_ms,
      signingDigest32: args.signingDigest32,
      serverPresignatureId: prepareResponse.server_presignature_id,
      clientSignatureShare32,
    });
    const finalized = await finalizeRouterAbEcdsaDerivationEvmDigestSigningV1({
      relayServerUrl: relayerUrl,
      credential: args.credential,
      request: finalizeRequest,
    });
    const signature65 = base64UrlDecode(finalized.signature65_b64u);
    if (signature65.length !== 65) {
      return {
        ok: false,
        code: 'internal',
        message: `Router A/B ECDSA derivation returned invalid signature length (expected 65, got ${signature65.length})`,
      };
    }
    try {
      await verifySecp256k1RecoverableSignatureAgainstPublicKey33Wasm({
        digest32: args.signingDigest32,
        signature65,
        publicKey33: groupPublicKey33,
        workerCtx: args.workerCtx,
      });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: `Router A/B ECDSA derivation returned a signature that does not recover to the threshold group public key: ${recoverableSignatureErrorMessage(error)}`,
      };
    }
    return {
      ok: true,
      signature65,
      signature65B64u: finalized.signature65_b64u,
      rB64u: base64UrlEncode(signature65.slice(0, 32)),
      sB64u: base64UrlEncode(signature65.slice(32, 64)),
      recId: signature65[64],
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Router A/B ECDSA derivation signing failed',
    );
    if (isExpiredRouterAbEcdsaDerivationPresignatureError(msg)) {
      return { ok: false, code: 'pool_entry_expired', message: msg };
    }
    return { ok: false, code: 'router_ab_sign_failed', message: msg };
  } finally {
    zeroizeBytes(clientSignatureShare32);
    if (poolKey && foregroundStarted) finishForegroundSign(poolKey);
  }
}

export async function signRouterAbEcdsaDerivationDigestWithPool(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  credential: RouterAbWalletSessionCredential;
  keyHandle?: EcdsaKeyHandle;
  signingDigest32: Uint8Array;
  clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource;
  expiresAtMs: number;
  workerCtx: WorkerOperationContext;
}): Promise<RouterAbEcdsaDerivationCoordinatorResult> {
  const signingIdentity = routerAbEcdsaDerivationSigningIdentityFromScope(args.scope);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    return {
      ok: false,
      code: 'invalid_pool_fill_expiry',
      message: 'Router A/B ECDSA derivation pool fill expiry is unavailable or expired',
    };
  }
  const firstAttempt = await signRouterAbEcdsaDerivationDigestWithPoolHit({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    credential: args.credential,
    signingDigest32: args.signingDigest32,
    clientSigningMaterial: args.clientSigningMaterial,
    expiresAtMs,
    workerCtx: args.workerCtx,
  });
  if (
    firstAttempt.ok ||
    (firstAttempt.code !== 'pool_empty' && firstAttempt.code !== 'pool_entry_expired')
  ) {
    return firstAttempt;
  }

  const refill = await refillRouterAbEcdsaDerivationClientPresignaturePool({
    relayerUrl: args.relayerUrl,
    keyHandle: args.keyHandle,
    ecdsaThresholdKeyId: signingIdentity.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: signingIdentity.clientVerifyingShareB64u,
    clientSigningMaterial: args.clientSigningMaterial,
    thresholdEcdsaPublicKeyB64u: signingIdentity.thresholdEcdsaPublicKeyB64u,
    credential: args.credential,
    routerAbEcdsaDerivationPoolFill: {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: args.scope,
      expiresAtMs,
    },
    workerCtx: args.workerCtx,
  });
  if (!refill.ok) return refill;

  return await signRouterAbEcdsaDerivationDigestWithPoolHit({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    credential: args.credential,
    signingDigest32: args.signingDigest32,
    clientSigningMaterial: args.clientSigningMaterial,
    expiresAtMs,
    workerCtx: args.workerCtx,
  });
}

export async function refillRouterAbEcdsaDerivationClientPresignaturePool(
  args: RouterAbEcdsaDerivationClientPresignatureRefillInput,
): Promise<{ ok: true; presignatureId: string } | RouterAbEcdsaDerivationCoordinatorError> {
  try {
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      scope: args.routerAbEcdsaDerivationPoolFill.scope,
    });
    const startedGeneration = getClientPresignaturePoolGeneration(poolKey);
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });
    const poolFillInitKeySelector = resolveRouterAbEcdsaDerivationPoolFillInitKeySelector({
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    });
    if (!poolFillInitKeySelector.ok) return poolFillInitKeySelector;

    const generated = await runPresignHandshake({
      relayerUrl: args.relayerUrl,
      poolFillInitKeySelector: poolFillInitKeySelector.value,
      clientSigningMaterial: args.clientSigningMaterial,
      groupPublicKey33,
      credential: args.credential,
      requestTag: 'background_presign_pool_refill',
      routerAbEcdsaDerivationPoolFill: args.routerAbEcdsaDerivationPoolFill,
      workerCtx: args.workerCtx,
    });
    if (!generated.ok) return generated;

    if (getClientPresignaturePoolGeneration(poolKey) !== startedGeneration) {
      return {
        ok: false,
        code: 'invalidated',
        message: 'Router A/B ECDSA derivation presignature pool invalidated',
      };
    }
    pushClientPresignature(poolKey, generated.presignature);
    return { ok: true, presignatureId: generated.presignature.presignatureId };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Router A/B ECDSA derivation presignature refill failed',
    );
    return { ok: false, code: 'internal', message: msg };
  }
}

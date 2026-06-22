import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaHssEvmDigestSigningRequestV1,
  parseRouterAbEcdsaHssNormalSigningScopeV1,
  routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import type {
  RouterAbEcdsaHssPresignaturePoolPolicy,
  RouterAbEcdsaHssPresignaturePoolPolicyInput,
} from '@/core/types/seams';
import { DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY } from '@/core/config/defaultConfigs';
import {
  addSecp256k1PublicKeys33Wasm,
  type ThresholdEcdsaPresignProgressWasm,
  validateSecp256k1PublicKey33Wasm,
} from '../../chains/evm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  routerAbEcdsaHssPresignaturePoolFillInit,
  routerAbEcdsaHssPresignaturePoolFillStep,
  type RouterAbEcdsaHssPresignaturePoolFill,
} from './poolFillRoutes';
import type { RouterAbEcdsaHssPoolFillInitKeySelector } from './poolFillRoutes';
import {
  finalizeRouterAbEcdsaHssEvmDigestSigningV1,
  prepareRouterAbEcdsaHssEvmDigestSigningV1,
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

export type RouterAbEcdsaHssClientPresignatureRefillInput = {
  relayerUrl: string;
  keyHandle?: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource;
  thresholdEcdsaPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  credential: RouterAbWalletSessionCredential;
  routerAbEcdsaHssPoolFill: RouterAbEcdsaHssPresignaturePoolFill;
  workerCtx: WorkerOperationContext;
};

export type RouterAbEcdsaHssClientPresignatureRefillScheduleResult = {
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

export type RouterAbEcdsaHssClientSigningMaterialSource = {
  kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1';
  initClientPresignSession: (input: {
    sessionId: string;
    participantIds: number[];
    clientParticipantId: number;
    threshold: number;
    groupPublicKey33: Uint8Array;
    workerCtx: WorkerOperationContext;
  }) => Promise<ThresholdEcdsaPresignProgressWasm>;
  stepClientPresignSession: (input: {
    sessionId: string;
    relayerParticipantId: number;
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
    participantIds: number[];
    clientParticipantId: number;
    groupPublicKey33: Uint8Array;
    expectedPresignBigR33: Uint8Array;
    digest32: Uint8Array;
    entropy32: Uint8Array;
    workerCtx: WorkerOperationContext;
  }) => Promise<Uint8Array>;
};

type RouterAbEcdsaHssClientPresignatureRef = {
  presignatureId: string;
  bigRB64u: string;
  materialHandle: string;
  createdAtMs: number;
};

type RouterAbEcdsaHssCoordinatorError = {
  ok: false;
  code: string;
  message: string;
};

type RouterAbEcdsaHssCoordinatorOk = {
  ok: true;
  signature65: Uint8Array;
  signature65B64u: string;
  rB64u: string;
  sB64u: string;
  recId: number;
};

export type RouterAbEcdsaHssCoordinatorResult =
  | RouterAbEcdsaHssCoordinatorOk
  | RouterAbEcdsaHssCoordinatorError;

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function zeroizeRouterAbEcdsaHssClientPresignatureList(
  presignatures?: RouterAbEcdsaHssClientPresignatureRef[] | null,
): void {
  if (!Array.isArray(presignatures)) return;
}

function assertRouterAbEcdsaHssClientSigningMaterialSource(
  source: RouterAbEcdsaHssClientSigningMaterialSource,
): void {
  if (source?.kind !== 'router_ab_ecdsa_hss_client_signing_material_source_v1') {
    throw new Error('Router A/B ECDSA-HSS client signing material source is required');
  }
}

const MAX_HANDSHAKE_STEPS = 64;
const ROUTER_AB_ECDSA_HSS_SIGNING_TTL_MS = 60_000;
const PRESIGN_REFILL_AUTHORITY_LOCK_PREFIX = 'w3a:router-ab-ecdsa-hss:presignature-refill:';
const clientPresignaturePool = new Map<string, RouterAbEcdsaHssClientPresignatureRef[]>();
const clientPresignatureRefillInFlightByPoolKey = new Map<string, Promise<void>>();
const foregroundSignInFlightByPoolKey = new Map<string, number>();
const clientPresignaturePoolGenerationByPoolKey = new Map<string, number>();

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

export function resolveRouterAbEcdsaHssPresignaturePoolPolicy(
  input?: RouterAbEcdsaHssPresignaturePoolPolicyInput | RouterAbEcdsaHssPresignaturePoolPolicy,
): RouterAbEcdsaHssPresignaturePoolPolicy {
  const source = input || DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY;
  const targetDepth = normalizePresignPoolTargetDepth(
    source.targetDepth,
    DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY.targetDepth,
  );
  const lowWatermark = normalizePresignPoolLowWatermark(
    source.lowWatermark,
    DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY.lowWatermark,
    targetDepth,
  );
  return {
    enabled:
      typeof source.enabled === 'boolean'
        ? source.enabled
        : DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY.enabled,
    targetDepth,
    lowWatermark,
    maxRefillInFlight: normalizeIntInRange(
      source.maxRefillInFlight,
      DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY.maxRefillInFlight,
      1,
      8,
    ),
    refillAttemptTimeoutMs: normalizeIntInRange(
      source.refillAttemptTimeoutMs,
      DEFAULT_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_POLICY.refillAttemptTimeoutMs,
      5_000,
      120_000,
    ),
  };
}

function createClientPresignSessionId(): string {
  return secureRandomId('c-presign', 32, 'client presign session IDs');
}

function normalizeParticipantIds(participantIds: number[] | undefined): number[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(participantIds);
  if (!normalized) {
    throw new Error(
      '[router-ab-ecdsa-hss] Missing participantIds; reconnect ECDSA signing session before signing',
    );
  }
  return normalized;
}

function resolveParticipantRoles(args: {
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
}): { clientParticipantId: number; relayerParticipantId: number } {
  const clientParticipantId = Number.isFinite(args.clientParticipantId)
    ? Math.floor(Number(args.clientParticipantId))
    : args.participantIds[0];
  const relayerParticipantId = Number.isFinite(args.relayerParticipantId)
    ? Math.floor(Number(args.relayerParticipantId))
    : args.participantIds[1];
  if (!Number.isFinite(clientParticipantId) || !Number.isFinite(relayerParticipantId)) {
    throw new Error(
      '[router-ab-ecdsa-hss] Missing client/relayer participant IDs; reconnect ECDSA signing session before signing',
    );
  }
  if (clientParticipantId === relayerParticipantId) {
    throw new Error('[router-ab-ecdsa-hss] clientParticipantId must differ from relayerParticipantId');
  }
  if (
    !args.participantIds.includes(clientParticipantId) ||
    !args.participantIds.includes(relayerParticipantId)
  ) {
    throw new Error('[router-ab-ecdsa-hss] participant role IDs must be members of participantIds');
  }
  return { clientParticipantId, relayerParticipantId };
}

function makePresignaturePoolKey(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  participantIds: number[];
}): string {
  const relayerUrl = String(args.relayerUrl || '')
    .trim()
    .replace(/\/+$/g, '');
  const parsedScope = parseRouterAbEcdsaHssNormalSigningScopeV1(args.scope);
  const participantIds = normalizeParticipantIds(args.participantIds);
  const scopeIdentityB64u = base64UrlEncode(
    routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1(parsedScope),
  );
  return [relayerUrl, scopeIdentityB64u, participantIds.join(',')].join('|');
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

function popClientPresignature(poolKey: string): RouterAbEcdsaHssClientPresignatureRef | null {
  const list = clientPresignaturePool.get(poolKey);
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
  item: RouterAbEcdsaHssClientPresignatureRef,
): void {
  const list = clientPresignaturePool.get(poolKey) || [];
  list.push(item);
  clientPresignaturePool.set(poolKey, list);
}

function getClientPresignaturePoolDepth(poolKey: string): number {
  return clientPresignaturePool.get(poolKey)?.length || 0;
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

export function clearAllRouterAbEcdsaHssClientPresignatures(): void {
  zeroizeRouterAbEcdsaHssClientPresignatureList(Array.from(clientPresignaturePool.values()).flat());
  clientPresignaturePool.clear();
  clientPresignatureRefillInFlightByPoolKey.clear();
  foregroundSignInFlightByPoolKey.clear();
  clientPresignaturePoolGenerationByPoolKey.clear();
}

export function clearRouterAbEcdsaHssClientPresignaturesForLane(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  participantIds: number[];
}): void {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    participantIds: args.participantIds,
  });
  bumpClientPresignaturePoolGeneration(poolKey);
  zeroizeRouterAbEcdsaHssClientPresignatureList(clientPresignaturePool.get(poolKey));
  clientPresignaturePool.delete(poolKey);
  clientPresignatureRefillInFlightByPoolKey.delete(poolKey);
}

export function getRouterAbEcdsaHssClientPresignaturePoolDepth(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  participantIds: number[];
}): number {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    participantIds: args.participantIds,
  });
  return getClientPresignaturePoolDepth(poolKey);
}

export function scheduleRouterAbEcdsaHssClientPresignaturePoolRefill(
  args: RouterAbEcdsaHssClientPresignatureRefillInput & {
    poolPolicy?: RouterAbEcdsaHssPresignaturePoolPolicyInput | RouterAbEcdsaHssPresignaturePoolPolicy;
    targetDepth?: number;
    triggerIfDepthAtOrBelow?: number;
  },
): RouterAbEcdsaHssClientPresignatureRefillScheduleResult {
  const finalizeUnschedule = (
    reason: RouterAbEcdsaHssClientPresignatureRefillScheduleResult['reason'],
    depth: number,
    targetDepth: number,
  ): RouterAbEcdsaHssClientPresignatureRefillScheduleResult => {
    return { scheduled: false, reason, depth, targetDepth };
  };
  try {
    const policy = resolveRouterAbEcdsaHssPresignaturePoolPolicy(args.poolPolicy);
    const participantIds = normalizeParticipantIds(args.participantIds);
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      scope: args.routerAbEcdsaHssPoolFill.scope,
      participantIds,
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

    const refillInput: RouterAbEcdsaHssClientPresignatureRefillInput = {
      relayerUrl: args.relayerUrl,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
      clientSigningMaterial: args.clientSigningMaterial,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      credential: args.credential,
      routerAbEcdsaHssPoolFill: args.routerAbEcdsaHssPoolFill,
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
            const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
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
      'Missing thresholdEcdsaPublicKeyB64u (or relayerVerifyingShareB64u fallback) for Router A/B ECDSA-HSS signing',
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
  poolFillInitKeySelector: RouterAbEcdsaHssPoolFillInitKeySelector;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource;
  groupPublicKey33: Uint8Array;
  credential: RouterAbWalletSessionCredential;
  requestTag?: string;
  routerAbEcdsaHssPoolFill: RouterAbEcdsaHssPresignaturePoolFill;
  workerCtx: WorkerOperationContext;
}): Promise<
  { ok: true; presignature: RouterAbEcdsaHssClientPresignatureRef } | RouterAbEcdsaHssCoordinatorError
> {
  assertRouterAbEcdsaHssClientSigningMaterialSource(args.clientSigningMaterial);
  const init = await routerAbEcdsaHssPresignaturePoolFillInit({
    relayerUrl: args.relayerUrl,
    ...args.poolFillInitKeySelector,
    count: 1,
    walletSessionJwt: args.credential.walletSessionJwt,
    requestTag: args.requestTag,
    poolFill: args.routerAbEcdsaHssPoolFill,
  });
  if (!init.ok) {
    return {
      ok: false,
      code: init.code || 'presign_init_failed',
      message: init.message || 'Router A/B ECDSA-HSS pool-fill init failed',
    };
  }

  const presignSessionId = String(init.presignSessionId || '').trim();
  if (!presignSessionId) {
    return {
      ok: false,
      code: 'internal',
      message: 'Router A/B ECDSA-HSS pool-fill init returned empty presignSessionId',
    };
  }

  const localSessionId = createClientPresignSessionId();

  let localPresignatureHandle: string | null = null;
  let localBigR33: Uint8Array | null = null;
  let serverPresignatureId: string | null = null;
  let serverBigRB64u: string | null = null;
  let serverDone = false;
  let stageForServer: 'triples' | 'presign' = 'triples';
  let pendingClientOutgoing = [] as Uint8Array[];
  let pendingServerOutgoing = fromB64uMessages(init.outgoingMessagesB64u);
  let shouldAbortLocalSession = true;

  try {
    const localInit = await args.clientSigningMaterial.initClientPresignSession({
      sessionId: localSessionId,
      participantIds: args.participantIds,
      clientParticipantId: args.clientParticipantId,
      threshold: 2,
      groupPublicKey33: args.groupPublicKey33,
      workerCtx: args.workerCtx,
    });
    pendingClientOutgoing = [...localInit.outgoingMessages];
    if (
      localInit.stage === 'triples_done' ||
      localInit.stage === 'presign' ||
      localInit.stage === 'done'
    ) {
      stageForServer = 'presign';
    }
    if (localInit.presignatureHandle && localInit.presignatureBigR33) {
      localPresignatureHandle = localInit.presignatureHandle;
      localBigR33 = localInit.presignatureBigR33;
      shouldAbortLocalSession = false;
    }

    for (let i = 0; i < MAX_HANDSHAKE_STEPS; i++) {
      if (pendingServerOutgoing.length > 0 && !localPresignatureHandle) {
        const localStepped = await args.clientSigningMaterial.stepClientPresignSession({
          sessionId: localSessionId,
          relayerParticipantId: args.relayerParticipantId,
          stage: stageForServer,
          incomingMessages: pendingServerOutgoing,
          workerCtx: args.workerCtx,
        });
        pendingServerOutgoing = [];
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (
          localStepped.stage === 'triples_done' ||
          localStepped.stage === 'presign' ||
          localStepped.stage === 'done'
        ) {
          stageForServer = 'presign';
        }
        if (localStepped.presignatureHandle && localStepped.presignatureBigR33) {
          localPresignatureHandle = localStepped.presignatureHandle;
          localBigR33 = localStepped.presignatureBigR33;
          shouldAbortLocalSession = false;
        }
      }

      if (!serverDone) {
        const stepArgs = {
          relayerUrl: args.relayerUrl,
          presignSessionId,
          stage: stageForServer,
          outgoingMessagesB64u: toB64uMessages(pendingClientOutgoing),
          walletSessionJwt: args.credential.walletSessionJwt,
          requestTag: args.requestTag,
        } as const;
        const stepped = await routerAbEcdsaHssPresignaturePoolFillStep(stepArgs);
        pendingClientOutgoing = [];
        if (!stepped.ok) {
          return {
            ok: false,
            code: stepped.code || 'presign_step_failed',
            message: stepped.message || 'Router A/B ECDSA-HSS pool-fill step failed',
          };
        }
        pendingServerOutgoing = fromB64uMessages(stepped.outgoingMessagesB64u);
        if (stepped.stage === 'presign' || stepped.stage === 'done') {
          stageForServer = 'presign';
        }
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
          relayerParticipantId: args.relayerParticipantId,
          stage: stageForServer,
          incomingMessages: [],
          workerCtx: args.workerCtx,
        });
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.presignatureHandle && localStepped.presignatureBigR33) {
          localPresignatureHandle = localStepped.presignatureHandle;
          localBigR33 = localStepped.presignatureBigR33;
          shouldAbortLocalSession = false;
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
      const localBigRB64u = base64UrlEncode(localBigR33);
      if (localBigRB64u !== serverBigRB64u) {
        return {
          ok: false,
          code: 'presign_mismatch',
          message: 'Client/server presignature mismatch (bigR mismatch)',
        };
      }

      return {
        ok: true,
        presignature: {
          presignatureId: serverPresignatureId,
          bigRB64u: localBigRB64u,
          materialHandle: localPresignatureHandle,
          createdAtMs: Date.now(),
        },
      };
    } finally {
      zeroizeBytes(localBigR33);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Router A/B ECDSA-HSS pool-fill handshake failed',
    );
    return { ok: false, code: 'presign_failed', message: msg };
  } finally {
    zeroizeBytes(localBigR33);
    if (shouldAbortLocalSession) {
      await args.clientSigningMaterial.abortClientPresignSession({
        sessionId: localSessionId,
        workerCtx: args.workerCtx,
      }).catch(() => {});
    }
  }
}

function routerAbEcdsaHssSigningIdentityFromScope(scope: RouterAbEcdsaHssNormalSigningScopeV1): {
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  thresholdEcdsaPublicKeyB64u: string;
} {
  const parsed = parseRouterAbEcdsaHssNormalSigningScopeV1(scope);
  return {
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(parsed.context.ecdsa_threshold_key_id),
    clientVerifyingShareB64u: parseEcdsaClientVerifyingShareB64u(
      parsed.public_identity.client_public_key33_b64u,
    ),
    thresholdEcdsaPublicKeyB64u: parsed.public_identity.threshold_public_key33_b64u,
  };
}

function resolveRouterAbEcdsaHssPoolFillInitKeySelector(args: {
  keyHandle?: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
}):
  | { ok: true; value: RouterAbEcdsaHssPoolFillInitKeySelector }
  | { ok: false; code: 'invalid_args'; message: string } {
  if (args.keyHandle) {
    const keyHandle = formatEcdsaKeyHandleForWire(args.keyHandle);
    return { ok: true, value: { keyHandle } };
  }
  return {
    ok: false,
    code: 'invalid_args',
    message: 'Missing keyHandle for Router A/B ECDSA-HSS pool-fill init selector',
  };
}

export async function signRouterAbEcdsaHssDigestWithPoolHit(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  credential: RouterAbWalletSessionCredential;
  signingDigest32: Uint8Array;
  clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource;
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  expiresAtMs?: number;
  workerCtx: WorkerOperationContext;
}): Promise<RouterAbEcdsaHssCoordinatorResult> {
  let poolKey: string | null = null;
  let foregroundStarted = false;
  let presignature: RouterAbEcdsaHssClientPresignatureRef | null = null;
  let clientSignatureShare32: Uint8Array | null = null;
  try {
    const relayerUrl = String(args.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    if (!relayerUrl) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing relayerUrl for Router A/B ECDSA-HSS signing',
      };
    }
    const signingIdentity = routerAbEcdsaHssSigningIdentityFromScope(args.scope);
    const ecdsaThresholdKeyId = signingIdentity.ecdsaThresholdKeyId;
    if (!ecdsaThresholdKeyId) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing ecdsaThresholdKeyId for Router A/B ECDSA-HSS signing',
      };
    }
    const clientVerifyingShareB64u = signingIdentity.clientVerifyingShareB64u;
    if (!clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing clientVerifyingShareB64u for Router A/B ECDSA-HSS signing',
      };
    }
    if (!(args.signingDigest32 instanceof Uint8Array) || args.signingDigest32.length !== 32) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'signingDigest32 must be 32 bytes for Router A/B ECDSA-HSS signing',
      };
    }
    const participantIds = normalizeParticipantIds(args.participantIds);
    const { clientParticipantId } = resolveParticipantRoles({
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
    });
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: signingIdentity.thresholdEcdsaPublicKeyB64u,
      workerCtx: args.workerCtx,
    });

    poolKey = makePresignaturePoolKey({
      relayerUrl,
      scope: args.scope,
      participantIds,
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
        message: 'Router A/B ECDSA-HSS client presignature pool is empty',
      };
    }

    const expiresAtMs =
      Number.isSafeInteger(args.expiresAtMs) && Number(args.expiresAtMs) > Date.now()
        ? Math.floor(Number(args.expiresAtMs))
        : Date.now() + ROUTER_AB_ECDSA_HSS_SIGNING_TTL_MS;
    const prepareRequest = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope: args.scope,
      requestId: secureRandomId('router-ab-ecdsa-sign', 32, 'Router A/B ECDSA-HSS sign request'),
      clientPresignatureId: presignature.presignatureId,
      expiresAtMs,
      signingDigest32: args.signingDigest32,
    });
    const prepareResponse = await prepareRouterAbEcdsaHssEvmDigestSigningV1({
      relayServerUrl: relayerUrl,
      credential: args.credential,
      request: prepareRequest,
    });
    if (prepareResponse.server_big_r33_b64u !== presignature.bigRB64u) {
      return {
        ok: false,
        code: 'presign_mismatch',
        message: 'Router A/B ECDSA-HSS SigningWorker returned a different presignature bigR',
      };
    }

    const bigR33 = base64UrlDecode(presignature.bigRB64u);
    const entropy32 = base64UrlDecode(prepareResponse.rerandomization_entropy32_b64u);
    try {
      if (bigR33.length !== 33) {
        return {
          ok: false,
          code: 'internal',
          message: 'Router A/B ECDSA-HSS presign bigR must decode to 33 bytes',
        };
      }
      if (entropy32.length !== 32) {
        return {
          ok: false,
          code: 'internal',
          message: 'Router A/B ECDSA-HSS rerandomization entropy must decode to 32 bytes',
        };
      }

      clientSignatureShare32 = await args.clientSigningMaterial.computeSignatureShareFromPresignatureHandle({
        materialHandle: presignature.materialHandle,
        participantIds,
        clientParticipantId,
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
        message: `Invalid Router A/B ECDSA-HSS client signature share length (expected 32, got ${clientSignatureShare32.length})`,
      };
    }

    const finalizeRequest = buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1({
      scope: args.scope,
      requestId: prepareRequest.request_id,
      budgetReservationId: prepareResponse.budget_reservation_id,
      budgetOperationId: prepareResponse.budget_operation_id,
      expiresAtMs: prepareRequest.expires_at_ms,
      signingDigest32: args.signingDigest32,
      serverPresignatureId: prepareResponse.server_presignature_id,
      clientSignatureShare32,
    });
    const finalized = await finalizeRouterAbEcdsaHssEvmDigestSigningV1({
      relayServerUrl: relayerUrl,
      credential: args.credential,
      request: finalizeRequest,
    });
    const signature65 = base64UrlDecode(finalized.signature65_b64u);
    if (signature65.length !== 65) {
      return {
        ok: false,
        code: 'internal',
        message: `Router A/B ECDSA-HSS returned invalid signature length (expected 65, got ${signature65.length})`,
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
        : e || 'Router A/B ECDSA-HSS signing failed',
    );
    return { ok: false, code: 'router_ab_sign_failed', message: msg };
  } finally {
    zeroizeBytes(clientSignatureShare32);
    if (poolKey && foregroundStarted) finishForegroundSign(poolKey);
  }
}

export async function signRouterAbEcdsaHssDigestWithPool(args: {
  relayerUrl: string;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  credential: RouterAbWalletSessionCredential;
  keyHandle?: EcdsaKeyHandle;
  signingDigest32: Uint8Array;
  clientSigningMaterial: RouterAbEcdsaHssClientSigningMaterialSource;
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  expiresAtMs?: number;
  workerCtx: WorkerOperationContext;
}): Promise<RouterAbEcdsaHssCoordinatorResult> {
  const signingIdentity = routerAbEcdsaHssSigningIdentityFromScope(args.scope);
  const firstAttempt = await signRouterAbEcdsaHssDigestWithPoolHit({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    credential: args.credential,
    signingDigest32: args.signingDigest32,
    clientSigningMaterial: args.clientSigningMaterial,
    participantIds: args.participantIds,
    clientParticipantId: args.clientParticipantId,
    relayerParticipantId: args.relayerParticipantId,
    expiresAtMs: args.expiresAtMs,
    workerCtx: args.workerCtx,
  });
  if (firstAttempt.ok || firstAttempt.code !== 'pool_empty') return firstAttempt;

  const expiresAtMs =
    Number.isSafeInteger(args.expiresAtMs) && Number(args.expiresAtMs) > Date.now()
      ? Math.floor(Number(args.expiresAtMs))
      : Date.now() + ROUTER_AB_ECDSA_HSS_SIGNING_TTL_MS;
  const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
    relayerUrl: args.relayerUrl,
    keyHandle: args.keyHandle,
    ecdsaThresholdKeyId: signingIdentity.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: signingIdentity.clientVerifyingShareB64u,
    participantIds: args.participantIds,
    clientParticipantId: args.clientParticipantId,
    relayerParticipantId: args.relayerParticipantId,
    clientSigningMaterial: args.clientSigningMaterial,
    thresholdEcdsaPublicKeyB64u: signingIdentity.thresholdEcdsaPublicKeyB64u,
    credential: args.credential,
    routerAbEcdsaHssPoolFill: {
      kind: 'router_ab_ecdsa_hss_signing_worker_pool',
      scope: args.scope,
      expiresAtMs,
    },
    workerCtx: args.workerCtx,
  });
  if (!refill.ok) return refill;

  return await signRouterAbEcdsaHssDigestWithPoolHit({
    relayerUrl: args.relayerUrl,
    scope: args.scope,
    credential: args.credential,
    signingDigest32: args.signingDigest32,
    clientSigningMaterial: args.clientSigningMaterial,
    participantIds: args.participantIds,
    clientParticipantId: args.clientParticipantId,
    relayerParticipantId: args.relayerParticipantId,
    expiresAtMs,
    workerCtx: args.workerCtx,
  });
}

export async function refillRouterAbEcdsaHssClientPresignaturePool(
  args: RouterAbEcdsaHssClientPresignatureRefillInput,
): Promise<{ ok: true; presignatureId: string } | RouterAbEcdsaHssCoordinatorError> {
  try {
    const participantIds = normalizeParticipantIds(args.participantIds);
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      scope: args.routerAbEcdsaHssPoolFill.scope,
      participantIds,
    });
    const startedGeneration = getClientPresignaturePoolGeneration(poolKey);
    const { clientParticipantId, relayerParticipantId } = resolveParticipantRoles({
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
    });
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });
    const poolFillInitKeySelector = resolveRouterAbEcdsaHssPoolFillInitKeySelector({
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    });
    if (!poolFillInitKeySelector.ok) return poolFillInitKeySelector;

    const generated = await runPresignHandshake({
      relayerUrl: args.relayerUrl,
      poolFillInitKeySelector: poolFillInitKeySelector.value,
      participantIds,
      clientParticipantId,
      relayerParticipantId,
      clientSigningMaterial: args.clientSigningMaterial,
      groupPublicKey33,
      credential: args.credential,
      requestTag: 'background_presign_pool_refill',
      routerAbEcdsaHssPoolFill: args.routerAbEcdsaHssPoolFill,
      workerCtx: args.workerCtx,
    });
    if (!generated.ok) return generated;

    if (getClientPresignaturePoolGeneration(poolKey) !== startedGeneration) {
      return {
        ok: false,
        code: 'invalidated',
        message: 'Router A/B ECDSA-HSS presignature pool invalidated',
      };
    }
    pushClientPresignature(poolKey, generated.presignature);
    return { ok: true, presignatureId: generated.presignature.presignatureId };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Router A/B ECDSA-HSS presignature refill failed',
    );
    return { ok: false, code: 'internal', message: msg };
  }
}

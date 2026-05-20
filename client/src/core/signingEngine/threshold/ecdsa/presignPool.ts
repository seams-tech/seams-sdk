import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type {
  ThresholdEcdsaPresignPoolPolicy,
  ThresholdEcdsaPresignPoolPolicyInput,
} from '@/core/types/seams';
import { DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY } from '@/core/config/defaultConfigs';
import {
  addSecp256k1PublicKeys33Wasm,
  mapAdditiveShareToThresholdSignaturesShare2pWasm,
  thresholdEcdsaComputeSignatureShareWasm,
  thresholdEcdsaPresignSessionAbortWasm,
  thresholdEcdsaPresignSessionInitWasm,
  thresholdEcdsaPresignSessionStepWasm,
  validateSecp256k1PublicKey33Wasm,
} from '../../chains/evm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { ecdsaPresignInit, ecdsaPresignStep, ecdsaSignFinalize, ecdsaSignInit } from './sign';
import type { ThresholdSessionKind } from '../sessionPolicy';
import type { ThresholdEcdsaPresignInitKeySelector } from './sign';

export type ThresholdEcdsaClientPresignatureRefillInput = {
  relayerUrl: string;
  keyHandle?: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  clientSigningShare32: Uint8Array;
  thresholdEcdsaPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  sessionKind?: ThresholdSessionKind;
  thresholdSessionAuthToken?: string;
  workerCtx: WorkerOperationContext;
};

export type ThresholdEcdsaClientPresignatureRefillScheduleResult = {
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

type ThresholdEcdsaClientPresignatureShare = {
  presignatureId: string;
  bigRB64u: string;
  kShare32: Uint8Array;
  sigmaShare32: Uint8Array;
  createdAtMs: number;
};

type ThresholdEcdsaCoordinatorError = {
  ok: false;
  code: string;
  message: string;
};

type ThresholdEcdsaCoordinatorOk = {
  ok: true;
  signature65: Uint8Array;
  signature65B64u: string;
  rB64u: string;
  sB64u: string;
  recId: number;
};

export type ThresholdEcdsaCoordinatorResult =
  | ThresholdEcdsaCoordinatorOk
  | ThresholdEcdsaCoordinatorError;

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function zeroizeThresholdEcdsaClientPresignatureShare(
  presignature?: ThresholdEcdsaClientPresignatureShare | null,
): void {
  if (!presignature) return;
  zeroizeBytes(presignature.kShare32);
  zeroizeBytes(presignature.sigmaShare32);
}

function zeroizeThresholdEcdsaClientPresignatureList(
  presignatures?: ThresholdEcdsaClientPresignatureShare[] | null,
): void {
  if (!Array.isArray(presignatures)) return;
  for (const presignature of presignatures) {
    zeroizeThresholdEcdsaClientPresignatureShare(presignature);
  }
}

const MAX_HANDSHAKE_STEPS = 64;
const PRESIGN_REFILL_AUTHORITY_LOCK_PREFIX = 'w3a:threshold-ecdsa:presign-refill:';
const clientPresignaturePool = new Map<string, ThresholdEcdsaClientPresignatureShare[]>();
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

export function resolveThresholdEcdsaPresignPoolPolicy(
  input?: ThresholdEcdsaPresignPoolPolicyInput | ThresholdEcdsaPresignPoolPolicy,
): ThresholdEcdsaPresignPoolPolicy {
  const source = input || DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY;
  const targetDepth = normalizePresignPoolTargetDepth(
    source.targetDepth,
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.targetDepth,
  );
  const lowWatermark = normalizePresignPoolLowWatermark(
    source.lowWatermark,
    DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.lowWatermark,
    targetDepth,
  );
  return {
    enabled:
      typeof source.enabled === 'boolean'
        ? source.enabled
        : DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.enabled,
    targetDepth,
    lowWatermark,
    maxRefillInFlight: normalizeIntInRange(
      source.maxRefillInFlight,
      DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.maxRefillInFlight,
      1,
      8,
    ),
    refillAttemptTimeoutMs: normalizeIntInRange(
      source.refillAttemptTimeoutMs,
      DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY.refillAttemptTimeoutMs,
      5_000,
      120_000,
    ),
  };
}

function createClientPresignSessionId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (typeof c?.randomUUID === 'function') return `c-presign-${c.randomUUID()}`;
  return `c-presign-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function normalizeParticipantIds(participantIds: number[] | undefined): number[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(participantIds);
  if (!normalized) {
    throw new Error(
      '[threshold-ecdsa] Missing participantIds; reconnect threshold session before signing',
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
      '[threshold-ecdsa] Missing client/relayer participant IDs; reconnect threshold session before signing',
    );
  }
  if (clientParticipantId === relayerParticipantId) {
    throw new Error('[threshold-ecdsa] clientParticipantId must differ from relayerParticipantId');
  }
  if (
    !args.participantIds.includes(clientParticipantId) ||
    !args.participantIds.includes(relayerParticipantId)
  ) {
    throw new Error('[threshold-ecdsa] participant role IDs must be members of participantIds');
  }
  return { clientParticipantId, relayerParticipantId };
}

function makePresignaturePoolKey(args: {
  relayerUrl: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
}): string {
  const relayerUrl = String(args.relayerUrl || '')
    .trim()
    .replace(/\/+$/g, '');
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const participantIds = normalizeParticipantIds(args.participantIds);
  if (!ecdsaThresholdKeyId) {
    throw new Error('[threshold-ecdsa] Missing ecdsaThresholdKeyId for presign pool identity');
  }
  return [relayerUrl, ecdsaThresholdKeyId, participantIds.join(',')].join('|');
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

function popClientPresignature(poolKey: string): ThresholdEcdsaClientPresignatureShare | null {
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
  item: ThresholdEcdsaClientPresignatureShare,
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

export function clearAllThresholdEcdsaClientPresignatures(): void {
  zeroizeThresholdEcdsaClientPresignatureList(Array.from(clientPresignaturePool.values()).flat());
  clientPresignaturePool.clear();
  clientPresignatureRefillInFlightByPoolKey.clear();
  foregroundSignInFlightByPoolKey.clear();
  clientPresignaturePoolGenerationByPoolKey.clear();
}

export function clearThresholdEcdsaClientPresignaturesForLane(args: {
  relayerUrl: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
}): void {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
  });
  bumpClientPresignaturePoolGeneration(poolKey);
  zeroizeThresholdEcdsaClientPresignatureList(clientPresignaturePool.get(poolKey));
  clientPresignaturePool.delete(poolKey);
  clientPresignatureRefillInFlightByPoolKey.delete(poolKey);
}

export function getThresholdEcdsaClientPresignaturePoolDepth(args: {
  relayerUrl: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
}): number {
  const poolKey = makePresignaturePoolKey({
    relayerUrl: args.relayerUrl,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
  });
  return getClientPresignaturePoolDepth(poolKey);
}

export function scheduleThresholdEcdsaClientPresignaturePoolRefill(
  args: ThresholdEcdsaClientPresignatureRefillInput & {
    poolPolicy?: ThresholdEcdsaPresignPoolPolicyInput | ThresholdEcdsaPresignPoolPolicy;
    targetDepth?: number;
    triggerIfDepthAtOrBelow?: number;
  },
): ThresholdEcdsaClientPresignatureRefillScheduleResult {
  const finalizeUnschedule = (
    reason: ThresholdEcdsaClientPresignatureRefillScheduleResult['reason'],
    depth: number,
    targetDepth: number,
  ): ThresholdEcdsaClientPresignatureRefillScheduleResult => {
    zeroizeBytes(args.clientSigningShare32);
    return { scheduled: false, reason, depth, targetDepth };
  };
  try {
    const policy = resolveThresholdEcdsaPresignPoolPolicy(args.poolPolicy);
    const participantIds = normalizeParticipantIds(args.participantIds);
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
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

    const refillInput: ThresholdEcdsaClientPresignatureRefillInput = {
      relayerUrl: args.relayerUrl,
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
      clientSigningShare32: args.clientSigningShare32,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      sessionKind: args.sessionKind,
      thresholdSessionAuthToken: args.thresholdSessionAuthToken,
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
            const refill = await refillThresholdEcdsaClientPresignaturePool({
              ...refillInput,
              clientSigningShare32: refillInput.clientSigningShare32.slice(),
            });
            if (!refill.ok) return;
          }
        },
      });
      if (authority !== 'acquired') return;
    })()
      .catch(() => {})
      .finally(() => {
        zeroizeBytes(refillInput.clientSigningShare32);
        const inFlight = clientPresignatureRefillInFlightByPoolKey.get(poolKey);
        if (inFlight === refillTask) {
          clientPresignatureRefillInFlightByPoolKey.delete(poolKey);
        }
      });
    clientPresignatureRefillInFlightByPoolKey.set(poolKey, refillTask);
    return { scheduled: true, reason: 'scheduled', depth, targetDepth };
  } catch {
    zeroizeBytes(args.clientSigningShare32);
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
      'Missing thresholdEcdsaPublicKeyB64u (or relayerVerifyingShareB64u fallback) for threshold-ecdsa signing',
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
  presignInitKeySelector: ThresholdEcdsaPresignInitKeySelector;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  clientSigningShare32: Uint8Array;
  groupPublicKey33: Uint8Array;
  sessionKind: ThresholdSessionKind;
  thresholdSessionAuthToken?: string;
  requestTag?: string;
  workerCtx: WorkerOperationContext;
}): Promise<
  { ok: true; presignature: ThresholdEcdsaClientPresignatureShare } | ThresholdEcdsaCoordinatorError
> {
  const init = await ecdsaPresignInit({
    relayerUrl: args.relayerUrl,
    ...args.presignInitKeySelector,
    count: 1,
    sessionKind: args.sessionKind,
    thresholdSessionAuthToken: args.thresholdSessionAuthToken,
    requestTag: args.requestTag,
  });
  if (!init.ok) {
    return {
      ok: false,
      code: init.code || 'presign_init_failed',
      message: init.message || 'threshold-ecdsa presign/init failed',
    };
  }

  const presignSessionId = String(init.presignSessionId || '').trim();
  if (!presignSessionId) {
    return {
      ok: false,
      code: 'internal',
      message: 'threshold-ecdsa presign/init returned empty presignSessionId',
    };
  }

  const localSessionId = createClientPresignSessionId();
  const clientThresholdSigningShare32 = await mapAdditiveShareToThresholdSignaturesShare2pWasm({
    additiveShare32: args.clientSigningShare32,
    participantId: args.clientParticipantId,
    workerCtx: args.workerCtx,
  });

  let localDonePresignature97: Uint8Array | null = null;
  let serverPresignatureId: string | null = null;
  let serverBigRB64u: string | null = null;
  let serverDone = false;
  let stageForServer: 'triples' | 'presign' = 'triples';
  let pendingClientOutgoing = [] as Uint8Array[];
  let pendingServerOutgoing = fromB64uMessages(init.outgoingMessagesB64u);
  let shouldAbortLocalSession = true;

  try {
    const localInit = await thresholdEcdsaPresignSessionInitWasm({
      sessionId: localSessionId,
      participantIds: args.participantIds,
      clientParticipantId: args.clientParticipantId,
      threshold: 2,
      clientThresholdSigningShare32,
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
    if (localInit.presignature97) {
      localDonePresignature97 = localInit.presignature97;
      shouldAbortLocalSession = false;
    }

    for (let i = 0; i < MAX_HANDSHAKE_STEPS; i++) {
      if (pendingServerOutgoing.length > 0 && !localDonePresignature97) {
        const localStepped = await thresholdEcdsaPresignSessionStepWasm({
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
        if (localStepped.presignature97) {
          localDonePresignature97 = localStepped.presignature97;
          shouldAbortLocalSession = false;
        }
      }

      if (!serverDone) {
        const stepped = await ecdsaPresignStep({
          relayerUrl: args.relayerUrl,
          presignSessionId,
          stage: stageForServer,
          outgoingMessagesB64u: toB64uMessages(pendingClientOutgoing),
          sessionKind: args.sessionKind,
          thresholdSessionAuthToken: args.thresholdSessionAuthToken,
          requestTag: args.requestTag,
        });
        pendingClientOutgoing = [];
        if (!stepped.ok) {
          return {
            ok: false,
            code: stepped.code || 'presign_step_failed',
            message: stepped.message || 'threshold-ecdsa presign/step failed',
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

      if (localDonePresignature97 && serverPresignatureId && serverBigRB64u) {
        break;
      }

      if (
        !pendingServerOutgoing.length &&
        !pendingClientOutgoing.length &&
        !localDonePresignature97
      ) {
        const localStepped = await thresholdEcdsaPresignSessionStepWasm({
          sessionId: localSessionId,
          relayerParticipantId: args.relayerParticipantId,
          stage: stageForServer,
          incomingMessages: [],
          workerCtx: args.workerCtx,
        });
        pendingClientOutgoing.push(...localStepped.outgoingMessages);
        if (localStepped.presignature97) {
          localDonePresignature97 = localStepped.presignature97;
          shouldAbortLocalSession = false;
        }
      }
    }

    if (!localDonePresignature97) {
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
    if (localDonePresignature97.length !== 97) {
      return {
        ok: false,
        code: 'internal',
        message: `Invalid local presignature bytes (expected 97, got ${localDonePresignature97.length})`,
      };
    }

    const bigR33 = localDonePresignature97.slice(0, 33);
    const kShare32 = localDonePresignature97.slice(33, 65);
    const sigmaShare32 = localDonePresignature97.slice(65, 97);
    try {
      const localBigRB64u = base64UrlEncode(bigR33);
      if (localBigRB64u !== serverBigRB64u) {
        return {
          ok: false,
          code: 'presign_mismatch',
          message: 'Client/server presignature mismatch (bigR mismatch)',
        };
      }

      const pooledKShare32 = kShare32.slice();
      const pooledSigmaShare32 = sigmaShare32.slice();
      return {
        ok: true,
        presignature: {
          presignatureId: serverPresignatureId,
          bigRB64u: localBigRB64u,
          kShare32: pooledKShare32,
          sigmaShare32: pooledSigmaShare32,
          createdAtMs: Date.now(),
        },
      };
    } finally {
      zeroizeBytes(localDonePresignature97);
      zeroizeBytes(kShare32);
      zeroizeBytes(sigmaShare32);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'threshold-ecdsa presign handshake failed',
    );
    return { ok: false, code: 'presign_failed', message: msg };
  } finally {
    zeroizeBytes(clientThresholdSigningShare32);
    zeroizeBytes(localDonePresignature97);
    if (shouldAbortLocalSession) {
      await thresholdEcdsaPresignSessionAbortWasm({
        sessionId: localSessionId,
        workerCtx: args.workerCtx,
      }).catch(() => {});
    }
  }
}

function resolveThresholdEcdsaPresignInitRequestSelector(args: {
  keyHandle?: string;
  ecdsaThresholdKeyId: string;
}):
  | { ok: true; value: ThresholdEcdsaPresignInitKeySelector }
  | { ok: false; code: 'invalid_args'; message: string } {
  const keyHandle = String(args.keyHandle || '').trim();
  if (keyHandle) {
    return { ok: true, value: { keyHandle } };
  }
  return {
    ok: false,
    code: 'invalid_args',
    message: 'Missing keyHandle for threshold-ecdsa presign/init selector',
  };
}

export async function signThresholdEcdsaDigestWithPool(args: {
  relayerUrl: string;
  keyHandle?: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  mpcSessionId: string;
  signingDigest32: Uint8Array;
  clientSigningShare32: Uint8Array;
  participantIds: number[];
  clientParticipantId?: number;
  relayerParticipantId?: number;
  thresholdEcdsaPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  sessionKind?: ThresholdSessionKind;
  thresholdSessionAuthToken?: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaCoordinatorResult> {
  try {
    const relayerUrl = String(args.relayerUrl || '')
      .trim()
      .replace(/\/+$/g, '');
    if (!relayerUrl)
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing relayerUrl for threshold-ecdsa signing',
      };
    const relayerKeyId = String(args.relayerKeyId || '').trim();
    if (!relayerKeyId)
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing relayerKeyId for threshold-ecdsa signing',
      };
    const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
    if (!ecdsaThresholdKeyId) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing ecdsaThresholdKeyId for threshold-ecdsa signing',
      };
    }
    const presignInitKeySelector = resolveThresholdEcdsaPresignInitRequestSelector({
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId,
    });
    if (!presignInitKeySelector.ok) return presignInitKeySelector;
    const mpcSessionId = String(args.mpcSessionId || '').trim();
    if (!mpcSessionId)
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing mpcSessionId for threshold-ecdsa signing',
      };
    const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
    if (!clientVerifyingShareB64u) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'Missing clientVerifyingShareB64u for threshold-ecdsa signing',
      };
    }
    if (!(args.signingDigest32 instanceof Uint8Array) || args.signingDigest32.length !== 32) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'signingDigest32 must be 32 bytes for threshold-ecdsa signing',
      };
    }
    if (
      !(args.clientSigningShare32 instanceof Uint8Array) ||
      args.clientSigningShare32.length !== 32
    ) {
      return {
        ok: false,
        code: 'invalid_args',
        message: 'clientSigningShare32 must be 32 bytes for threshold-ecdsa signing',
      };
    }

    const participantIds = normalizeParticipantIds(args.participantIds);
    const { clientParticipantId, relayerParticipantId } = resolveParticipantRoles({
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
    });
    const sessionKind: ThresholdSessionKind = args.sessionKind || 'jwt';

    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });

    const poolKey = makePresignaturePoolKey({
      relayerUrl,
      ecdsaThresholdKeyId,
      participantIds,
    });
    startForegroundSign(poolKey);
    let presignature: ThresholdEcdsaClientPresignatureShare | null = null;
    try {
      presignature = popClientPresignature(poolKey);
      if (!presignature) {
        await waitForInFlightRefill(poolKey);
        presignature = popClientPresignature(poolKey);
      }
      if (!presignature) {
        const generated = await runPresignHandshake({
          relayerUrl,
          presignInitKeySelector: presignInitKeySelector.value,
          relayerKeyId,
          clientVerifyingShareB64u,
          participantIds,
          clientParticipantId,
          relayerParticipantId,
          clientSigningShare32: args.clientSigningShare32,
          groupPublicKey33,
          sessionKind,
          thresholdSessionAuthToken: args.thresholdSessionAuthToken,
          workerCtx: args.workerCtx,
        });
        if (!generated.ok) return generated;
        presignature = generated.presignature;
      }

      let signInit = await ecdsaSignInit({
        relayerUrl,
        mpcSessionId,
        relayerKeyId,
        signingDigest32: args.signingDigest32,
        presignatureId: presignature.presignatureId,
      });
      if (!signInit.ok && signInit.code === 'pool_empty') {
        zeroizeThresholdEcdsaClientPresignatureShare(presignature);
        presignature = null;
        await waitForInFlightRefill(poolKey);
        presignature = popClientPresignature(poolKey) || null;
        if (!presignature) {
          const generated = await runPresignHandshake({
            relayerUrl,
            presignInitKeySelector: presignInitKeySelector.value,
            relayerKeyId,
            clientVerifyingShareB64u,
            participantIds,
            clientParticipantId,
            relayerParticipantId,
            clientSigningShare32: args.clientSigningShare32,
            groupPublicKey33,
            sessionKind,
            thresholdSessionAuthToken: args.thresholdSessionAuthToken,
            workerCtx: args.workerCtx,
          });
          if (!generated.ok) return generated;
          presignature = generated.presignature;
        }
        signInit = await ecdsaSignInit({
          relayerUrl,
          mpcSessionId,
          relayerKeyId,
          signingDigest32: args.signingDigest32,
          presignatureId: presignature.presignatureId,
        });
      }
      if (!signInit.ok) {
        return {
          ok: false,
          code: signInit.code || 'sign_init_failed',
          message: signInit.message || 'threshold-ecdsa sign/init failed',
        };
      }

      const signingSessionId = String(signInit.signingSessionId || '').trim();
      const relayerRound1 = signInit.relayerRound1 || {};
      const entropyB64u = String(relayerRound1.entropyB64u || '').trim();
      if (!signingSessionId || !entropyB64u) {
        return {
          ok: false,
          code: 'internal',
          message: 'threshold-ecdsa sign/init returned incomplete round-1 payload',
        };
      }
      const relayerBigRB64u = String(relayerRound1.bigRB64u || '').trim();
      if (relayerBigRB64u && relayerBigRB64u !== presignature.bigRB64u) {
        return {
          ok: false,
          code: 'presign_mismatch',
          message:
            'Relayer selected a different presignature than the client pool item (bigR mismatch)',
        };
      }

      const bigR33 = base64UrlDecode(presignature.bigRB64u);
      const kShare32 = presignature.kShare32;
      const sigmaShare32 = presignature.sigmaShare32;
      const entropy32 = base64UrlDecode(entropyB64u);
      let clientSignatureShare32: Uint8Array | null = null;
      try {
        if (bigR33.length !== 33)
          return { ok: false, code: 'internal', message: 'presign bigR must decode to 33 bytes' };
        if (kShare32.length !== 32)
          return { ok: false, code: 'internal', message: 'presign kShare must decode to 32 bytes' };
        if (sigmaShare32.length !== 32)
          return {
            ok: false,
            code: 'internal',
            message: 'presign sigmaShare must decode to 32 bytes',
          };
        if (entropy32.length !== 32)
          return {
            ok: false,
            code: 'internal',
            message: 'relayer entropy must decode to 32 bytes',
          };

        clientSignatureShare32 = await thresholdEcdsaComputeSignatureShareWasm({
          participantIds,
          clientParticipantId,
          groupPublicKey33,
          presignBigR33: bigR33,
          presignKShare32: kShare32,
          presignSigmaShare32: sigmaShare32,
          digest32: args.signingDigest32,
          entropy32,
          workerCtx: args.workerCtx,
        });
        if (clientSignatureShare32.length !== 32) {
          return {
            ok: false,
            code: 'internal',
            message: `Invalid client signature share length (expected 32, got ${clientSignatureShare32.length})`,
          };
        }

        const finalized = await ecdsaSignFinalize({
          relayerUrl,
          signingSessionId,
          clientSignatureShare32,
        });
        if (!finalized.ok) {
          return {
            ok: false,
            code: finalized.code || 'sign_finalize_failed',
            message: finalized.message || 'threshold-ecdsa sign/finalize failed',
          };
        }

        const signature65B64u = String(finalized.relayerRound2?.signature65B64u || '').trim();
        if (!signature65B64u) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ecdsa sign/finalize returned empty signature65B64u',
          };
        }
        const signature65 = base64UrlDecode(signature65B64u);
        if (signature65.length !== 65) {
          return {
            ok: false,
            code: 'internal',
            message: `threshold-ecdsa sign/finalize returned invalid signature length (expected 65, got ${signature65.length})`,
          };
        }

        return {
          ok: true,
          signature65,
          signature65B64u,
          rB64u: String(finalized.relayerRound2?.rB64u || '').trim(),
          sB64u: String(finalized.relayerRound2?.sB64u || '').trim(),
          recId: Number(finalized.relayerRound2?.recId ?? signature65[64]),
        };
      } finally {
        zeroizeBytes(bigR33);
        zeroizeBytes(kShare32);
        zeroizeBytes(sigmaShare32);
        zeroizeBytes(entropy32);
        zeroizeBytes(clientSignatureShare32);
      }
    } finally {
      zeroizeThresholdEcdsaClientPresignatureShare(presignature);
      zeroizeBytes(args.clientSigningShare32);
      finishForegroundSign(poolKey);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'threshold-ecdsa coordinator failed',
    );
    return { ok: false, code: 'internal', message: msg };
  }
}

export async function refillThresholdEcdsaClientPresignaturePool(
  args: ThresholdEcdsaClientPresignatureRefillInput,
): Promise<{ ok: true; presignatureId: string } | ThresholdEcdsaCoordinatorError> {
  try {
    const participantIds = normalizeParticipantIds(args.participantIds);
    const poolKey = makePresignaturePoolKey({
      relayerUrl: args.relayerUrl,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds,
    });
    const startedGeneration = getClientPresignaturePoolGeneration(poolKey);
    const { clientParticipantId, relayerParticipantId } = resolveParticipantRoles({
      participantIds,
      clientParticipantId: args.clientParticipantId,
      relayerParticipantId: args.relayerParticipantId,
    });
    const sessionKind: ThresholdSessionKind = args.sessionKind || 'jwt';
    const groupPublicKey33 = await resolveGroupPublicKey33({
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u: args.thresholdEcdsaPublicKeyB64u,
      relayerVerifyingShareB64u: args.relayerVerifyingShareB64u,
      workerCtx: args.workerCtx,
    });
    const presignInitKeySelector = resolveThresholdEcdsaPresignInitRequestSelector({
      keyHandle: args.keyHandle,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    });
    if (!presignInitKeySelector.ok) return presignInitKeySelector;

    const generated = await runPresignHandshake({
      relayerUrl: args.relayerUrl,
      presignInitKeySelector: presignInitKeySelector.value,
      relayerKeyId: args.relayerKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      participantIds,
      clientParticipantId,
      relayerParticipantId,
      clientSigningShare32: args.clientSigningShare32,
      groupPublicKey33,
      sessionKind,
      thresholdSessionAuthToken: args.thresholdSessionAuthToken,
      requestTag: 'background_presign_pool_refill',
      workerCtx: args.workerCtx,
    });
    if (!generated.ok) return generated;

    if (getClientPresignaturePoolGeneration(poolKey) !== startedGeneration) {
      return {
        ok: false,
        code: 'invalidated',
        message: 'threshold-ecdsa presign pool invalidated',
      };
    }
    pushClientPresignature(poolKey, generated.presignature);
    return { ok: true, presignatureId: generated.presignature.presignatureId };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'threshold-ecdsa presign refill failed',
    );
    return { ok: false, code: 'internal', message: msg };
  } finally {
    zeroizeBytes(args.clientSigningShare32);
  }
}

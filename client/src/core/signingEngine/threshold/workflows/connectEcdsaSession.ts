import type {
  ThresholdIndexedDbPort,
  ThresholdPrfFirstCachePort,
  ThresholdWebAuthnPromptPort,
} from '../webauthn';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { bootstrapEcdsaSession } from './bootstrapEcdsaSession';

type EcdsaSessionKind = 'jwt' | 'cookie';

/**
 * Wallet-origin helper for threshold-ECDSA session bootstrap.
 * - runs staged `ecdsa-hss` bootstrap via `bootstrapEcdsaSession(...)`
 * - validates that returned `relayerKeyId` matches the requested key id
 */
export async function connectEcdsaSession(args: {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache?: ThresholdPrfFirstCachePort;
  relayerUrl: string;
  relayerKeyId: string;
  userId: string;
  participantIds?: number[];
  sessionKind?: EcdsaSessionKind;
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  clientVerifyingShareB64u?: string;
  code?: string;
  message?: string;
}> {
  const requestedRelayerKeyId = String(args.relayerKeyId || '').trim();
  if (!requestedRelayerKeyId) {
    return { ok: false, code: 'invalid_args', message: 'Missing relayerKeyId' };
  }

  const bootstrap = await bootstrapEcdsaSession({
    indexedDB: args.indexedDB,
    touchIdPrompt: args.touchIdPrompt,
    prfFirstCache: args.prfFirstCache,
    relayerUrl: args.relayerUrl,
    userId: String(args.userId || '').trim(),
    participantIds: args.participantIds,
    sessionKind: args.sessionKind as EcdsaSessionKind | undefined,
    sessionId: args.sessionId,
    ttlMs: args.ttlMs,
    remainingUses: args.remainingUses,
    workerCtx: args.workerCtx,
  });
  if (!bootstrap.ok) {
    return {
      ok: false,
      code: bootstrap.code || 'bootstrap_failed',
      message: bootstrap.message || 'Threshold bootstrap failed',
    };
  }

  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  if (!relayerKeyId) {
    return {
      ok: false,
      code: 'internal',
      message: 'Threshold bootstrap response missing relayerKeyId',
    };
  }
  if (relayerKeyId !== requestedRelayerKeyId) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'bootstrap relayerKeyId does not match requested relayerKeyId',
    };
  }
  const sessionId = String(bootstrap.sessionId || '').trim();
  if (!sessionId) {
    return {
      ok: false,
      code: 'internal',
      message: 'Threshold bootstrap response missing sessionId',
    };
  }
  return {
    ok: true,
    sessionId,
    expiresAtMs: bootstrap.expiresAtMs,
    remainingUses: bootstrap.remainingUses,
    jwt: bootstrap.jwt,
    clientVerifyingShareB64u: bootstrap.clientVerifyingShareB64u,
  };
}

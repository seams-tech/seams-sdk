import type { SigningAuthMode } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { ThresholdPrfFirstCachePeekPort } from '@/core/signingEngine/touchConfirm';
import type { KeyRef, SignRequest } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import { resolveThresholdSigningAuthMode } from './thresholdSigningSessionPlanner';

export function makeRequestId(prefix: string): string {
  const c = globalThis.crypto;
  if (c?.randomUUID && typeof c.randomUUID === 'function') return c.randomUUID();
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function inferDigest32FromSignRequest(req: SignRequest): Uint8Array {
  return req.kind === 'digest' ? req.digest32 : req.challenge32;
}

export function asThresholdEcdsaKeyRef(
  value: KeyRef | undefined,
): ThresholdEcdsaSecp256k1KeyRef | null {
  if (!value || typeof value !== 'object') return null;
  return value.type === 'threshold-ecdsa-secp256k1'
    ? (value as ThresholdEcdsaSecp256k1KeyRef)
    : null;
}

export async function resolveSigningAuthMode(args: {
  needsWebAuthn: boolean;
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef | null;
  touchConfirm: ThresholdPrfFirstCachePeekPort;
}): Promise<SigningAuthMode> {
  return await resolveThresholdSigningAuthMode({
    needsWebAuthn: args.needsWebAuthn,
    sessionId: args.thresholdEcdsaKeyRef?.thresholdSessionId,
    touchConfirm: args.touchConfirm,
    usesNeeded: 1,
  });
}

export function resolveKeyRefForSignRequest(args: {
  signReq: SignRequest;
  keyRefsByAlgorithm?: Partial<Record<SignRequest['algorithm'], KeyRef>>;
}): { signReq: SignRequest; keyRef: KeyRef } {
  const keyRef = args.keyRefsByAlgorithm?.[args.signReq.algorithm];
  if (!keyRef) {
    throw new Error(`[chains] missing keyRef for algorithm: ${args.signReq.algorithm}`);
  }
  return { signReq: args.signReq, keyRef };
}

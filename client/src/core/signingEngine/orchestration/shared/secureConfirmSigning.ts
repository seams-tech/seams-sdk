import type { SigningAuthMode } from '@/core/signingEngine/secureConfirm/confirmTxFlow/types';
import type { SecureConfirmWorkerManager } from '@/core/signingEngine/secureConfirm';
import type { KeyRef, SignRequest } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';

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
  secureConfirmWorkerManager: Pick<SecureConfirmWorkerManager, 'peekPrfFirstForThresholdSession'>;
}): Promise<SigningAuthMode> {
  if (args.needsWebAuthn) return 'webauthn';

  const thresholdSessionId = String(args.thresholdEcdsaKeyRef?.thresholdSessionId || '').trim();
  if (!thresholdSessionId) {
    throw new Error('[chains] Missing threshold signingSessionId; reconnect threshold session before signing');
  }

  const peek = await args.secureConfirmWorkerManager.peekPrfFirstForThresholdSession({
    sessionId: thresholdSessionId,
  });
  if (!peek.ok) {
    throw new Error(
      `[chains] threshold signingSession is ${peek.code}; reconnect threshold session before signing`,
    );
  }
  if (peek.remainingUses < 1) {
    throw new Error('[chains] threshold signingSession is exhausted; reconnect threshold session before signing');
  }
  return 'warmSession';
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

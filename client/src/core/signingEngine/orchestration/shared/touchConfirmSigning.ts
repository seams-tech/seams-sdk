import type {
  EmailOtpConfirmPrompt,
  SigningAuthPlan,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { WalletAuthPlan } from '@/core/signingEngine/auth';
import type { KeyRef, SignRequest } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
export { formatEmailOtpSentText } from '@/core/signingEngine/touchConfirm/shared/emailOtpPromptCopy';

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

export function signingAuthPlanFromWalletAuthPlan(
  plan: WalletAuthPlan,
  emailOtpPrompt?: EmailOtpConfirmPrompt,
): SigningAuthPlan {
  if (plan.kind === 'warmSession') {
    return {
      kind: 'warmSession',
      method: plan.method,
      accountId: plan.accountId,
      intent: plan.intent,
      ...(plan.curve ? { curve: plan.curve } : {}),
      ...(plan.signingRootId ? { signingRootId: plan.signingRootId } : {}),
      sessionId: plan.sessionId,
      ...(plan.retention !== undefined ? { retention: plan.retention } : {}),
      expiresAtMs: plan.expiresAtMs,
      remainingUses: plan.remainingUses,
    };
  }
  if (plan.kind === 'emailOtpReauth') {
    if (!emailOtpPrompt) {
      throw new Error('Email OTP signing auth plan requires an emailOtpPrompt');
    }
    return {
      kind: 'emailOtpReauth',
      method: 'email_otp',
      emailOtpPrompt,
    };
  }
  return {
    kind: 'passkeyReauth',
    method: 'passkey',
  };
}

export function emailOtpSigningAuthPlan(emailOtpPrompt: EmailOtpConfirmPrompt): SigningAuthPlan {
  return {
    kind: 'emailOtpReauth',
    method: 'email_otp',
    emailOtpPrompt,
  };
}

export function passkeySigningAuthPlan(): SigningAuthPlan {
  return {
    kind: 'passkeyReauth',
    method: 'passkey',
  };
}

export async function resolveTouchConfirmSigningAuth(args: {
  needsWebAuthn: boolean;
  walletAuthPlan?: WalletAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}): Promise<{
  touchConfirmAuthPayload: { signingAuthPlan: SigningAuthPlan };
}> {
  if (args.walletAuthPlan) {
    const signingAuthPlan = signingAuthPlanFromWalletAuthPlan(
      args.walletAuthPlan,
      args.emailOtpPrompt,
    );
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.emailOtpPrompt) {
    const signingAuthPlan = emailOtpSigningAuthPlan(args.emailOtpPrompt);
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  if (args.needsWebAuthn) {
    const signingAuthPlan = passkeySigningAuthPlan();
    return {
      touchConfirmAuthPayload: { signingAuthPlan },
    };
  }
  throw new Error('Signing auth resolution requires a concrete SigningAuthPlan');
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

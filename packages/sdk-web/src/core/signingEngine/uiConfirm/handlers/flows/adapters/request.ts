import {
  SigningAuthPlanKind,
  signingAuthModeFromSigningAuthPlan,
  type EmailOtpConfirmPrompt,
  type SigningAuthPlan,
  type SigningAuthMode,
} from '../../../../stepUpConfirmation/types';
import {
  type RegisterAccountPayload,
  type UserConfirmRequest,
  type SignIntentDigestPayload,
  type SignNep413Payload,
  type SignTransactionPayload,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { UserConfirmationType } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { isObject, isString } from '@shared/utils/validation';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';

/**
 * Validates secure-confirm requests (V2 only).
 * This deliberately rejects JSON strings and shorthand shapes.
 */
export function validateUserConfirmRequest(input: unknown): UserConfirmRequest {
  if (typeof input === 'string') {
    throw new Error(
      'Invalid secure confirm request: expected an object (JSON strings are not supported)',
    );
  }
  if (!isObject(input)) throw new Error('parsed is not an object');
  const p = input as {
    requestId?: unknown;
    type?: unknown;
    summary?: unknown;
    payload?: unknown;
  };
  if (!isString(p.requestId) || !p.requestId) throw new Error('missing requestId');
  if (!isString(p.type) || !p.type) throw new Error('missing type');
  if (p.summary === undefined || p.summary === null) throw new Error('missing summary');
  if (!isObject(p.summary) || Array.isArray(p.summary))
    throw new Error('invalid summary: expected an object');
  if (p.payload === undefined || p.payload === null) throw new Error('missing payload');
  if (!isObject(p.payload) || Array.isArray(p.payload))
    throw new Error('invalid payload: expected an object');
  assertSigningRequestUsesAuthPlanOnly(input as unknown as UserConfirmRequest);
  return input as unknown as UserConfirmRequest;
}

function assertSigningRequestUsesAuthPlanOnly(request: UserConfirmRequest): void {
  if (
    request.type !== UserConfirmationType.SIGN_TRANSACTION &&
    request.type !== UserConfirmationType.SIGN_NEP413_MESSAGE &&
    request.type !== UserConfirmationType.SIGN_INTENT_DIGEST
  ) {
    return;
  }

  const payload = ((request as { payload?: unknown }).payload ?? {}) as Record<string, unknown>;
  if (payload.signingAuthMode !== undefined) {
    throw new Error(
      'Invalid secure confirm request: signingAuthMode is not accepted; use signingAuthPlan',
    );
  }
  if (!isSigningAuthPlan(payload.signingAuthPlan)) {
    throw new Error('Invalid secure confirm request: missing or invalid signingAuthPlan');
  }
  if (payload.sessionPolicyDigest32 !== undefined) {
    throw new Error(
      'Invalid secure confirm request: sessionPolicyDigest32 is not accepted; use webauthnChallenge',
    );
  }
  if (
    request.type === UserConfirmationType.SIGN_INTENT_DIGEST &&
    (payload.signingAuthPlan as SigningAuthPlan).kind === SigningAuthPlanKind.PasskeyReauth &&
    !isWebAuthnChallenge(payload.webauthnChallenge)
  ) {
    throw new Error(
      'Invalid secure confirm request: passkey intent signing requires webauthnChallenge',
    );
  }
}

function isSigningAuthPlan(value: unknown): value is SigningAuthPlan {
  if (!isObject(value)) return false;
  const plan = value as { kind?: unknown; method?: unknown };
  if (plan.kind === SigningAuthPlanKind.WarmSession) {
    return plan.method === 'passkey' || plan.method === 'email_otp';
  }
  if (plan.kind === SigningAuthPlanKind.PasskeyReauth) return plan.method === 'passkey';
  if (plan.kind === SigningAuthPlanKind.EmailOtpReauth) return plan.method === 'email_otp';
  return false;
}

function isWebAuthnChallenge(value: unknown): boolean {
  if (!isObject(value)) return false;
  const challenge = value as {
    kind?: unknown;
    challengeB64u?: unknown;
    digest32B64u?: unknown;
    requestId?: unknown;
    thresholdSessionId?: unknown;
    signingGrantId?: unknown;
  };
  if (challenge.kind === 'intent_digest') return isString(challenge.challengeB64u);
  if (challenge.kind === 'threshold_session_policy') return isString(challenge.digest32B64u);
  if (challenge.kind === 'ecdsa_role_local_bootstrap') {
    return (
      isString(challenge.digest32B64u) &&
      isString(challenge.requestId) &&
      isString(challenge.thresholdSessionId) &&
      isString(challenge.signingGrantId)
    );
  }
  return false;
}

export function assertNoForbiddenMainThreadSigningSecrets(request: UserConfirmRequest): void {
  if (
    request.type !== UserConfirmationType.SIGN_TRANSACTION &&
    request.type !== UserConfirmationType.SIGN_NEP413_MESSAGE
  ) {
    return;
  }

  const payload = ((request as { payload?: unknown }).payload ?? {}) as Record<string, unknown>;
  if (payload.prfOutput !== undefined) {
    throw new Error('Invalid secure confirm request: forbidden signing payload field prfOutput');
  }
  if (payload.wrapKeySeed !== undefined) {
    throw new Error('Invalid secure confirm request: forbidden signing payload field wrapKeySeed');
  }
  if (payload.wrapKeySalt !== undefined) {
    throw new Error('Invalid secure confirm request: forbidden signing payload field wrapKeySalt');
  }
}

export function getNearAccountId(request: UserConfirmRequest): string {
  switch (request.type) {
    case UserConfirmationType.SIGN_TRANSACTION:
      return getSignTransactionPayload(request).rpcCall.nearAccountId;
    case UserConfirmationType.SIGN_NEP413_MESSAGE:
      return (request.payload as SignNep413Payload).nearAccountId;
    case UserConfirmationType.SIGN_INTENT_DIGEST:
      return (request.payload as SignIntentDigestPayload).nearAccountId;
    case UserConfirmationType.REGISTER_ACCOUNT:
    case UserConfirmationType.LINK_DEVICE:
      return getRegisterAccountPayload(request).nearAccountId;
    case UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF: {
      const p = request.payload as { nearAccountId?: string };
      return p?.nearAccountId || '';
    }
    case UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI: {
      const p = request.payload as { nearAccountId?: string };
      return p?.nearAccountId || '';
    }
    default:
      return '';
  }
}

export function getWalletId(request: UserConfirmRequest): string {
  switch (request.type) {
    case UserConfirmationType.SIGN_TRANSACTION:
      return String(getSignTransactionPayload(request).walletId || '').trim();
    case UserConfirmationType.SIGN_NEP413_MESSAGE:
      return String((request.payload as SignNep413Payload).walletId || '').trim();
    default:
      return getNearAccountId(request);
  }
}

export function getTxCount(request: UserConfirmRequest): number {
  return request.type === UserConfirmationType.SIGN_TRANSACTION
    ? getSignTransactionPayload(request).txSigningRequests?.length || 1
    : 1;
}

export function getIntentDigest(request: UserConfirmRequest): string | undefined {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    const p = request?.payload as Partial<SignTransactionPayload> | undefined;
    return p?.intentDigest;
  }
  return request?.intentDigest;
}

export function getSignTransactionPayload(request: UserConfirmRequest): SignTransactionPayload {
  if (request.type !== UserConfirmationType.SIGN_TRANSACTION) {
    throw new Error(`Expected SIGN_TRANSACTION request, got ${request.type}`);
  }
  return request.payload as SignTransactionPayload;
}

export function getDisplayModel(request: UserConfirmRequest): TxDisplayModel | undefined {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    return getSignTransactionPayload(request).displayModel;
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    return (request.payload as SignNep413Payload).displayModel;
  }
  if (request.type === UserConfirmationType.SIGN_INTENT_DIGEST) {
    return (request.payload as SignIntentDigestPayload).displayModel;
  }
  return undefined;
}

export function getSigningAuthMode(request: UserConfirmRequest): SigningAuthMode | undefined {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    const payload = getSignTransactionPayload(request);
    return signingAuthModeFromSigningAuthPlan(payload.signingAuthPlan);
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    const payload = request.payload as SignNep413Payload;
    return signingAuthModeFromSigningAuthPlan(payload.signingAuthPlan);
  }
  if (request.type === UserConfirmationType.SIGN_INTENT_DIGEST) {
    const payload = request.payload as SignIntentDigestPayload;
    return signingAuthModeFromSigningAuthPlan(payload.signingAuthPlan);
  }
  return undefined;
}

export function getEmailOtpPrompt(request: UserConfirmRequest): EmailOtpConfirmPrompt | undefined {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    const payload = getSignTransactionPayload(request);
    return payload.signingAuthPlan?.kind === SigningAuthPlanKind.EmailOtpReauth
      ? payload.signingAuthPlan.emailOtpPrompt
      : payload.emailOtpPrompt;
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    const payload = request.payload as SignNep413Payload;
    return payload.signingAuthPlan?.kind === SigningAuthPlanKind.EmailOtpReauth
      ? payload.signingAuthPlan.emailOtpPrompt
      : payload.emailOtpPrompt;
  }
  if (request.type === UserConfirmationType.SIGN_INTENT_DIGEST) {
    const payload = request.payload as SignIntentDigestPayload;
    return payload.signingAuthPlan?.kind === SigningAuthPlanKind.EmailOtpReauth
      ? payload.signingAuthPlan.emailOtpPrompt
      : payload.emailOtpPrompt;
  }
  return undefined;
}

export function getNearPublicKeyStr(request: UserConfirmRequest): string | undefined {
  if (request.type === UserConfirmationType.SIGN_TRANSACTION) {
    const value = getSignTransactionPayload(request).nearPublicKeyStr;
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
  }
  if (request.type === UserConfirmationType.SIGN_NEP413_MESSAGE) {
    const value = (request.payload as SignNep413Payload).nearPublicKeyStr;
    return typeof value === 'string' && value.trim() ? value.trim() : undefined;
  }
  return undefined;
}

export function getRegisterAccountPayload(request: UserConfirmRequest): RegisterAccountPayload {
  if (
    request.type !== UserConfirmationType.REGISTER_ACCOUNT &&
    request.type !== UserConfirmationType.LINK_DEVICE
  ) {
    throw new Error(`Expected REGISTER_ACCOUNT or LINK_DEVICE request, got ${request.type}`);
  }
  return request.payload as RegisterAccountPayload;
}

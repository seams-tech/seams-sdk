import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../core/registrationContracts';
import { thresholdEd25519StatusCode } from '../threshold/statusCodes';
import type {
  RouterApiWalletRegistrationService,
  RouterApiWalletUnlockService,
} from './authServicePort';
import { parseWalletUnlockBackend } from './emailOtpRequestValidation';
import {
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoggedInWebhookEventDescriptor,
  type EmailOtpWebhookEventDescriptor,
} from './emailOtpSessionRouteHelpers';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from './routerAbEd25519YaoRecovery';
import {
  EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND,
  EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND,
  type WalletUnlockEmailOtpSessionRequestV1,
} from './walletUnlockEd25519YaoRequestValidation';

export type WalletUnlockRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type EmitWalletUnlockRouterApiWebhook = (input: {
  eventType: string;
  userId?: string;
  eventId?: string;
  payload: Record<string, unknown>;
}) => Promise<void>;

export type EmitWalletUnlockEmailOtpWebhook = (input: {
  descriptor: EmailOtpWebhookEventDescriptor;
  userId: string;
  walletId?: string;
}) => Promise<void>;

type WalletUnlockEd25519YaoSessionMaterialV1 = {
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
};

export type WalletUnlockEd25519YaoSessionSuccessV1 =
  | (WalletUnlockEd25519YaoSessionMaterialV1 & {
      readonly kind: typeof EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND;
    })
  | (WalletUnlockEd25519YaoSessionMaterialV1 & {
      readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
    });

type ExactLocalEmailOtpSessionRequest = WalletUnlockEmailOtpSessionRequestV1 & {
  readonly sessionIntent: Extract<
    WalletUnlockEmailOtpSessionRequestV1['sessionIntent'],
    { readonly kind: typeof EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND }
  >;
};

type MissingMaterialRecoveryRequest = WalletUnlockEmailOtpSessionRequestV1 & {
  readonly sessionIntent: Extract<
    WalletUnlockEmailOtpSessionRequestV1['sessionIntent'],
    { readonly kind: typeof EMAIL_OTP_MISSING_ED25519_MATERIAL_RECOVERY_KIND }
  >;
};

export type WalletUnlockEd25519YaoSessionContext =
  | { readonly kind: 'passkey_unlock' }
  | { readonly kind: 'email_otp_no_ed25519_session' }
  | {
      readonly kind: 'email_otp_exact_local_material';
      readonly request: ExactLocalEmailOtpSessionRequest;
      readonly provisionWalletSession: RouterApiWalletRegistrationService['recoverEd25519YaoEmailOtpWalletSession'];
    }
  | {
      readonly kind: 'email_otp_missing_material_recovery';
      readonly request: MissingMaterialRecoveryRequest;
      readonly recoverWalletSession: RouterApiWalletRegistrationService['recoverEd25519YaoEmailOtpWalletSession'];
    };

type VerifiedEmailOtpUnlockResult = Extract<
  Awaited<ReturnType<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>>,
  { readonly ok: true }
>;

type WalletUnlockEd25519YaoSessionResult =
  | { readonly ok: true; readonly value: WalletUnlockEd25519YaoSessionSuccessV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

function walletUnlockScopeMismatchResponse(): WalletUnlockEd25519YaoSessionResult {
  return {
    ok: false,
    response: {
      status: 403,
      body: {
        ok: false,
        code: 'scope_mismatch',
        message: 'Email OTP unlock proof does not match the requested Ed25519 wallet',
      },
    },
  };
}

function walletUnlockSessionFailureResponse(input: {
  readonly result: { readonly ok: false; readonly code: string; readonly message: string };
}): WalletUnlockEd25519YaoSessionResult {
  return {
    ok: false,
    response: {
      status: thresholdEd25519StatusCode(input.result),
      body: input.result,
    },
  };
}

async function provisionEmailOtpEd25519YaoSession(input: {
  readonly context: Extract<
    WalletUnlockEd25519YaoSessionContext,
    { kind: 'email_otp_exact_local_material' | 'email_otp_missing_material_recovery' }
  >;
  readonly verifiedUnlock: VerifiedEmailOtpUnlockResult;
}): Promise<WalletUnlockEd25519YaoSessionResult> {
  const request = input.context.request;
  if (
    input.verifiedUnlock.walletId !== request.walletId ||
    input.verifiedUnlock.orgId !== request.orgId
  ) {
    return walletUnlockScopeMismatchResponse();
  }

  switch (input.context.kind) {
    case 'email_otp_exact_local_material': {
      const provisioned = await input.context.provisionWalletSession({
        kind: 'router_ab_ed25519_yao_email_otp_local_session_v1',
        walletId: request.walletId,
        orgId: request.orgId,
        signerSlot: request.sessionIntent.signerSlot,
        remainingUses: request.sessionIntent.remainingUses,
        verifiedChallengeId: request.challengeId,
        verifiedProviderUserId: input.verifiedUnlock.providerUserId,
      });
      if (!provisioned.ok) return walletUnlockSessionFailureResponse({ result: provisioned });
      return {
        ok: true,
        value: {
          kind: EMAIL_OTP_EXACT_LOCAL_MATERIAL_SESSION_KIND,
          session: provisioned.session,
          capability: provisioned.capability,
        },
      };
    }
    case 'email_otp_missing_material_recovery': {
      const recovered = await input.context.recoverWalletSession({
        kind: 'router_ab_ed25519_yao_email_otp_recovery_session_v1',
        walletId: request.walletId,
        orgId: request.orgId,
        signerSlot: request.sessionIntent.signerSlot,
        remainingUses: request.sessionIntent.remainingUses,
        verifiedChallengeId: request.challengeId,
        verifiedProviderUserId: input.verifiedUnlock.providerUserId,
      });
      if (!recovered.ok) return walletUnlockSessionFailureResponse({ result: recovered });
      return {
        ok: true,
        value: {
          kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
          session: recovered.session,
          capability: recovered.capability,
        },
      };
    }
  }
}

export async function handleWalletUnlockChallengeRoute(input: {
  body: unknown;
  service: RouterApiWalletUnlockService;
}): Promise<WalletUnlockRouteResponse> {
  if (!input.body || typeof input.body !== 'object' || Array.isArray(input.body)) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Request body is required' },
    };
  }
  const body = input.body as Record<string, unknown>;
  const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
  if (!unlockBackend) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
    };
  }

  const result =
    unlockBackend === 'passkey'
      ? await input.service.createWebAuthnLoginOptions({
          userId: body.userId,
          rpId: body.rpId,
          ttlMs: body.ttlMs,
        })
      : await input.service.createEmailOtpUnlockChallenge({
          walletId: body.walletId,
          orgId: body.orgId,
          ttlMs: body.ttlMs,
        });

  return {
    status: result.ok ? 200 : result.code === 'internal' ? 500 : 400,
    body: {
      ...result,
      unlockBackend,
    },
  };
}

async function verifyPasskeyWalletUnlock(input: {
  readonly body: Record<string, unknown>;
  readonly challengeId: string;
  readonly origin: string | undefined;
  readonly service: RouterApiWalletUnlockService;
}) {
  if (!input.body.webauthn_authentication || typeof input.body.webauthn_authentication !== 'object') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: 'webauthn_authentication is required',
    } as const;
  }
  return await input.service.verifyWebAuthnLogin({
    challengeId: input.challengeId,
    webauthn_authentication: input.body.webauthn_authentication,
    expected_origin: input.origin,
  });
}

async function emitEmailOtpUnlockFailure(input: {
  readonly body: Record<string, unknown>;
  readonly challengeId: string;
  readonly code: string;
  readonly message: string;
  readonly emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
}): Promise<void> {
  const walletId = String(input.body.walletId || '').trim();
  if (!walletId) return;
  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'unlock_verify',
    code: input.code,
    message: input.message,
    challengeId: input.challengeId,
  })) {
    await input.emitEmailOtpWebhook({ descriptor, userId: walletId, walletId });
  }
}

async function emitSuccessfulWalletUnlock(input: {
  readonly unlockBackend: 'passkey' | typeof EMAIL_OTP_CHANNEL;
  readonly challengeId: string;
  readonly userId: string;
  readonly walletId: string;
  readonly emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  readonly emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
}): Promise<void> {
  await input.emitRouterApiWebhook({
    eventType: 'wallet.unlocked',
    userId: input.userId,
    eventId: input.challengeId,
    payload: {
      unlocked: true,
      unlockBackend: input.unlockBackend,
      challengeId: input.challengeId,
    },
  });
  if (input.unlockBackend !== EMAIL_OTP_CHANNEL) return;
  await input.emitEmailOtpWebhook({
    descriptor: emailOtpLoggedInWebhookEventDescriptor({
      challengeId: input.challengeId,
      otpChannel: EMAIL_OTP_CHANNEL,
      unlockBackend: EMAIL_OTP_CHANNEL,
    }),
    userId: input.userId,
    walletId: input.walletId,
  });
}

export async function handleWalletUnlockVerifyRoute(input: {
  body: unknown;
  origin?: string;
  service: RouterApiWalletUnlockService;
  emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
  ed25519YaoSession: WalletUnlockEd25519YaoSessionContext;
}): Promise<WalletUnlockRouteResponse> {
  if (!input.body || typeof input.body !== 'object' || Array.isArray(input.body)) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Request body is required' },
    };
  }
  const body = input.body as Record<string, unknown>;
  const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
  if (!unlockBackend) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
    };
  }
  const challengeId = String(body.challengeId || '').trim();
  if (!challengeId) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'challengeId is required' },
    };
  }

  if (unlockBackend === 'passkey') {
    if (input.ed25519YaoSession.kind !== 'passkey_unlock') {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: 'Passkey unlock context is invalid' },
      };
    }
    const result = await verifyPasskeyWalletUnlock({
      body,
      challengeId,
      origin: input.origin,
      service: input.service,
    });
    if (!result.ok || !result.verified) {
      return {
        status: result.code === 'internal' ? 500 : 400,
        body: { ...result, unlockBackend },
      };
    }
    const userId = String(result.userId || '').trim();
    if (!userId) {
      return {
        status: 500,
        body: { ok: false, code: 'internal', message: 'Verified passkey user is missing' },
      };
    }
    await input.service.markEmailOtpStrongAuthSatisfied({ walletId: userId });
    await emitSuccessfulWalletUnlock({
      unlockBackend,
      challengeId,
      userId,
      walletId: userId,
      emitRouterApiWebhook: input.emitRouterApiWebhook,
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: 200,
      body: { ok: true, unlocked: true, unlockBackend, userId },
    };
  }

  if (input.ed25519YaoSession.kind === 'passkey_unlock') {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Email OTP unlock context is invalid' },
    };
  }
  const result = await input.service.verifyEmailOtpUnlockProof({
    walletId: body.walletId,
    orgId: body.orgId,
    challengeId,
    unlockProof: body.unlockProof,
  });
  if (!result.ok || !result.verified) {
    await emitEmailOtpUnlockFailure({
      body,
      challengeId,
      code: String(result.code || 'unlock_verify_failed'),
      message: String(result.message || 'Email OTP unlock verification failed'),
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: result.code === 'internal' ? 500 : 400,
      body: { ...result, unlockBackend },
    };
  }

  if (input.ed25519YaoSession.kind === 'email_otp_no_ed25519_session') {
    await emitSuccessfulWalletUnlock({
      unlockBackend,
      challengeId,
      userId: result.userId,
      walletId: result.walletId,
      emitRouterApiWebhook: input.emitRouterApiWebhook,
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: 200,
      body: {
        ok: true,
        unlocked: true,
        unlockBackend,
        userId: result.userId,
      },
    };
  }
  const sessionResult = await provisionEmailOtpEd25519YaoSession({
    context: input.ed25519YaoSession,
    verifiedUnlock: result,
  });
  if (!sessionResult.ok) return sessionResult.response;
  await emitSuccessfulWalletUnlock({
    unlockBackend,
    challengeId,
    userId: result.userId,
    walletId: result.walletId,
    emitRouterApiWebhook: input.emitRouterApiWebhook,
    emitEmailOtpWebhook: input.emitEmailOtpWebhook,
  });
  return {
    status: 200,
    body: {
      ok: true,
      unlocked: true,
      unlockBackend,
      userId: result.userId,
      ed25519YaoSession: sessionResult.value,
    },
  };
}

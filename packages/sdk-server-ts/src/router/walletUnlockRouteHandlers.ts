import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
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
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
  type WalletUnlockEd25519YaoEmailOtpRecoveryRequestV1,
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

export type WalletUnlockEd25519YaoRecoverySuccessV1 = {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND;
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
};

export type WalletUnlockEd25519YaoRecoveryContext =
  | { readonly kind: 'not_requested' }
  | {
      readonly kind: 'requested';
      readonly request: WalletUnlockEd25519YaoEmailOtpRecoveryRequestV1;
      readonly recoverWalletSession: RouterApiWalletRegistrationService['recoverEd25519YaoEmailOtpWalletSession'];
    };

type VerifiedEmailOtpUnlockResult = Extract<
  Awaited<ReturnType<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>>,
  { readonly ok: true }
>;

type WalletUnlockEd25519YaoRecoveryResult =
  | { readonly ok: true; readonly value: WalletUnlockEd25519YaoRecoverySuccessV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

async function recoverEmailOtpEd25519YaoSession(input: {
  readonly context: Extract<WalletUnlockEd25519YaoRecoveryContext, { kind: 'requested' }>;
  readonly verifiedUnlock: VerifiedEmailOtpUnlockResult;
}): Promise<WalletUnlockEd25519YaoRecoveryResult> {
  const request = input.context.request;
  if (
    input.verifiedUnlock.walletId !== request.walletId ||
    input.verifiedUnlock.orgId !== request.orgId
  ) {
    return {
      ok: false,
      response: {
        status: 403,
        body: {
          ok: false,
          code: 'scope_mismatch',
          message: 'Email OTP unlock proof does not match the requested Ed25519 Yao wallet',
        },
      },
    };
  }
  const recovered = await input.context.recoverWalletSession({
    kind: 'router_ab_ed25519_yao_email_otp_recovery_session_v1',
    walletId: request.walletId,
    orgId: request.orgId,
    signerSlot: request.signerSlot,
    remainingUses: request.remainingUses,
    verifiedChallengeId: request.challengeId,
    verifiedProviderUserId: input.verifiedUnlock.providerUserId,
  });
  if (!recovered.ok) {
    return {
      ok: false,
      response: { status: thresholdEd25519StatusCode(recovered), body: recovered },
    };
  }
  return {
    ok: true,
    value: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
      session: recovered.session,
      capability: recovered.capability,
    },
  };
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

export async function handleWalletUnlockVerifyRoute(input: {
  body: unknown;
  origin?: string;
  service: RouterApiWalletUnlockService;
  emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
  ed25519YaoRecovery: WalletUnlockEd25519YaoRecoveryContext;
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

  const result =
    unlockBackend === 'passkey'
      ? await (async () => {
          if (!body.webauthn_authentication || typeof body.webauthn_authentication !== 'object') {
            return {
              ok: false,
              verified: false,
              code: 'invalid_body',
              message: 'webauthn_authentication is required',
            } as const;
          }
          return input.service.verifyWebAuthnLogin({
            challengeId,
            webauthn_authentication: body.webauthn_authentication,
            expected_origin: input.origin,
          });
        })()
      : await input.service.verifyEmailOtpUnlockProof({
          walletId: body.walletId,
          orgId: body.orgId,
          challengeId,
          unlockProof: body.unlockProof,
        });

  if (!result.ok || !result.verified) {
    if (unlockBackend === EMAIL_OTP_CHANNEL) {
      const walletId = String(body.walletId || '').trim();
      if (walletId) {
        for (const descriptor of emailOtpFailureWebhookEventDescriptors({
          source: 'unlock_verify',
          code: String(result.code || 'unlock_verify_failed'),
          message: String(result.message || 'Email OTP unlock verification failed'),
          challengeId,
        })) {
          await input.emitEmailOtpWebhook({
            descriptor,
            userId: walletId,
            walletId,
          });
        }
      }
    }
    return {
      status: result.code === 'internal' ? 500 : 400,
      body: { ...result, unlockBackend },
    };
  }

  if (unlockBackend === 'passkey') {
    await input.service.markEmailOtpStrongAuthSatisfied({ walletId: result.userId });
  }
  let ed25519YaoRecovery: WalletUnlockEd25519YaoRecoverySuccessV1 | null = null;
  if (input.ed25519YaoRecovery.kind === 'requested') {
    if (unlockBackend !== EMAIL_OTP_CHANNEL || !('providerUserId' in result)) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: 'Ed25519 Yao recovery requires verified Email OTP unlock proof',
        },
      };
    }
    const refreshed = await recoverEmailOtpEd25519YaoSession({
      context: input.ed25519YaoRecovery,
      verifiedUnlock: result,
    });
    if (!refreshed.ok) return refreshed.response;
    ed25519YaoRecovery = refreshed.value;
  }
  await input.emitRouterApiWebhook({
    eventType: 'wallet.unlocked',
    userId: result.userId,
    eventId: challengeId,
    payload: {
      unlocked: true,
      unlockBackend,
      challengeId,
    },
  });

  if (unlockBackend === EMAIL_OTP_CHANNEL) {
    const recoveredWalletId = String(
      (result as { walletId?: unknown }).walletId || body.walletId || '',
    ).trim();
    const recoveredUserId = String(result.userId || recoveredWalletId).trim();
    await input.emitEmailOtpWebhook({
      descriptor: emailOtpLoggedInWebhookEventDescriptor({
        challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
        unlockBackend,
      }),
      userId: recoveredUserId,
      ...(recoveredWalletId ? { walletId: recoveredWalletId } : {}),
    });
  }

  return {
    status: 200,
    body: {
      ok: true,
      unlocked: true,
      unlockBackend,
      ...(result.userId ? { userId: result.userId } : {}),
      ...(ed25519YaoRecovery ? { ed25519YaoRecovery } : {}),
    },
  };
}

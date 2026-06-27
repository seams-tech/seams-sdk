import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type { CloudflareRelayAuthService } from './authServicePort';
import { parseWalletUnlockBackend } from './emailOtpRequestValidation';
import {
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoggedInWebhookEventDescriptor,
  type EmailOtpWebhookEventDescriptor,
} from './emailOtpSessionRouteHelpers';

export type WalletUnlockRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type EmitWalletUnlockRelayWebhook = (input: {
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

export async function handleWalletUnlockChallengeRoute(input: {
  body: unknown;
  service: CloudflareRelayAuthService;
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
  service: CloudflareRelayAuthService;
  emitRelayWebhook: EmitWalletUnlockRelayWebhook;
  emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
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
          if (
            !body.webauthn_authentication ||
            typeof body.webauthn_authentication !== 'object'
          ) {
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
  await input.emitRelayWebhook({
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
    },
  };
}

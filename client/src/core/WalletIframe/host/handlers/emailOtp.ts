import type { HandlerDeps, HandlerMap, Req } from './types';
import { respondOkResult, withProgress } from './shared';
import type { EmailOtpEnrollmentResult } from '@/web/SeamsWeb/interfaces';
import { backupEmailOtpRecoveryCodes } from '@/web/SeamsWeb/emailOtpRecoveryCodeBackup';

function recordFromPayload(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function walletIdFromPayloadSession(value: unknown): string {
  const session = recordFromPayload(value);
  return String(session.walletId || '').trim();
}

async function acknowledgeEmailOtpBackupInIframe(input: {
  pm: ReturnType<HandlerDeps['getSeamsWeb']>;
  result: EmailOtpEnrollmentResult;
  nearAccountId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}) {
  return await backupEmailOtpRecoveryCodes({
    relayUrl: String(input.relayUrl || '').trim(),
    walletId: input.nearAccountId,
    enrollment: input.result,
    ...(input.relayUrl ? { relayUrl: input.relayUrl } : {}),
    ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
    acknowledge: async (args) => await input.pm.auth.acknowledgeEmailOtpRecoveryCodeBackup(args),
  });
}

export function createEmailOtpWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REQUEST_EMAIL_OTP_CHALLENGE: async (req: Req<'PM_REQUEST_EMAIL_OTP_CHALLENGE'>) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, relayUrl, appSessionJwt, operation } = req.payload!;
      const result = await pm.auth.requestEmailOtpChallenge({
        nearAccountId,
        ...(relayUrl ? { relayUrl } : {}),
        ...(appSessionJwt ? { appSessionJwt } : {}),
        ...(operation ? { operation } : {}),
      });
      respondOkResult(deps, req.requestId, result);
    },

    PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE: async (
      req: Req<'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const { nearAccountId, relayUrl, appSessionJwt } = req.payload!;
      const result = await pm.auth.requestEmailOtpEnrollmentChallenge({
        nearAccountId,
        ...(relayUrl ? { relayUrl } : {}),
        ...(appSessionJwt ? { appSessionJwt } : {}),
      });
      respondOkResult(deps, req.requestId, result);
    },

    PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE: async (
      req: Req<'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.auth.requestEmailOtpSigningSessionChallenge(req.payload!);
      respondOkResult(deps, req.requestId, result);
    },

    PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION: async (
      req: Req<'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.auth.exchangeGoogleEmailOtpSession(req.payload!);
      respondOkResult(deps, req.requestId, result);
    },

    PM_ENROLL_EMAIL_OTP: async (req: Req<'PM_ENROLL_EMAIL_OTP'>) => {
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const payload = withProgress(deps, req.requestId, rawPayload);
      const result = await pm.auth.enrollEmailOtp(
        payload as Parameters<typeof pm.auth.enrollEmailOtp>[0],
      );
      if (!('recoveryKeys' in result)) {
        respondOkResult(deps, req.requestId, result);
        return;
      }
      const acknowledged = await acknowledgeEmailOtpBackupInIframe({
        pm,
        result,
        nearAccountId: String(rawPayload.nearAccountId || '').trim(),
        relayUrl: typeof rawPayload.relayUrl === 'string' ? rawPayload.relayUrl : undefined,
        appSessionJwt:
          typeof rawPayload.appSessionJwt === 'string' ? rawPayload.appSessionJwt : undefined,
      });
      respondOkResult(deps, req.requestId, acknowledged);
    },

    PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY: async (
      req: Req<'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payload = withProgress(deps, req.requestId, req.payload || {});
      const result = await pm.auth.loginWithEmailOtpEcdsaCapability(
        payload as Parameters<typeof pm.auth.loginWithEmailOtpEcdsaCapability>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_REFRESH_EMAIL_OTP_SIGNING_SESSION: async (
      req: Req<'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payload = withProgress(deps, req.requestId, req.payload || {});
      const result = await pm.auth.refreshEmailOtpSigningSession(
        payload as Parameters<typeof pm.auth.refreshEmailOtpSigningSession>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY: async (
      req: Req<'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const payload = withProgress(deps, req.requestId, rawPayload);
      const result = await pm.auth.enrollAndLoginWithEmailOtpEcdsaCapability(
        payload as Parameters<typeof pm.auth.enrollAndLoginWithEmailOtpEcdsaCapability>[0],
      );
      if (!('recoveryKeys' in result.enrollment)) {
        respondOkResult(deps, req.requestId, result);
        return;
      }
      const acknowledgedEnrollment = await acknowledgeEmailOtpBackupInIframe({
        pm,
        result: result.enrollment,
        nearAccountId: walletIdFromPayloadSession(rawPayload.walletSession),
        relayUrl: typeof rawPayload.relayUrl === 'string' ? rawPayload.relayUrl : undefined,
        appSessionJwt:
          typeof rawPayload.appSessionJwt === 'string' ? rawPayload.appSessionJwt : undefined,
      });
      respondOkResult(deps, req.requestId, {
        ...result,
        enrollment: acknowledgedEnrollment,
      });
    },
  };
}

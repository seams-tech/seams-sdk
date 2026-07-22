import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOkResult, withProgress } from './shared';
import type {
  EmailOtpEnrollmentResult,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from '@/SeamsWeb/signingSurface/types';
import {
  backupEmailOtpRecoveryCodes,
  showEmailOtpRecoveryCodeBackupUi,
} from '../../../operations/authMethods/emailOtp/recoveryCodeBackup';
import { emailOtpRecoveryCodeBackupRepository } from '../../../../core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';
import type {
  PMGoogleEmailOtpWalletAuthRegistrationWireFlow,
  PMGoogleEmailOtpWalletAuthRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthWireFlow,
  PMGoogleEmailOtpWalletAuthWireResult,
} from '../../shared/messages';

function recordFromPayload(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function walletIdFromPayloadSession(value: unknown): string {
  const session = recordFromPayload(value);
  return String(session.walletId || '').trim();
}

function readRequiredString(record: Record<string, unknown>, field: string): string {
  const value = typeof record[field] === 'string' ? record[field].trim() : '';
  if (!value) {
    throw new Error(`Missing ${field}`);
  }
  return value;
}

function readOptionalString(record: Record<string, unknown>, field: string): string | undefined {
  const value = typeof record[field] === 'string' ? record[field].trim() : '';
  return value || undefined;
}

function assertNoGoogleRegistrationOtpFields(payload: unknown): void {
  const record = recordFromPayload(payload);
  const forbiddenFields = [
    'challengeId',
    'challenge_id',
    'otpCode',
    'otp_code',
    'otpDelivery',
    'otp_delivery',
    'delivery',
    'resend',
  ];
  const forbiddenField = forbiddenFields.find((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (forbiddenField) {
    throw new Error(`Google Email OTP registration message must not include ${forbiddenField}`);
  }
}

type GoogleEmailOtpWalletAuthHandleRecord = {
  flow: GoogleEmailOtpWalletAuthFlow;
  expiresAtMs: number;
};

const googleEmailOtpWalletAuthFlows = new Map<string, GoogleEmailOtpWalletAuthHandleRecord>();

function createFlowHandleId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `google-email-otp-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function flowToWire(
  flow: GoogleEmailOtpWalletAuthRegistrationFlow,
): PMGoogleEmailOtpWalletAuthRegistrationWireFlow;
function flowToWire(flow: GoogleEmailOtpWalletAuthFlow): PMGoogleEmailOtpWalletAuthWireFlow;
function flowToWire(flow: GoogleEmailOtpWalletAuthFlow): PMGoogleEmailOtpWalletAuthWireFlow {
  const flowHandleId = createFlowHandleId();
  googleEmailOtpWalletAuthFlows.set(flowHandleId, {
    flow,
    expiresAtMs: flow.expiresAtMs,
  });
  if (flow.mode === 'register') {
    return {
      kind: flow.kind,
      state: 'registration_ready',
      flowHandleId,
      flowId: flow.flowId,
      requestedMode: flow.requestedMode,
      mode: 'register',
      walletId: flow.walletId,
      emailHint: flow.emailHint,
      prompt: flow.prompt,
      expiresAtMs: flow.expiresAtMs,
    };
  }
  return {
    kind: flow.kind,
    state: 'challenge_sent',
    flowHandleId,
    flowId: flow.flowId,
    requestedMode: flow.requestedMode,
    mode: 'login',
    walletId: flow.walletId,
    emailHint: flow.emailHint,
    prompt: flow.prompt,
    delivery: flow.delivery,
    expiresAtMs: flow.expiresAtMs,
  };
}

function resultFlowToWire(
  result: GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>,
): PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthWireFlow> {
  return result.ok ? { ok: true, value: flowToWire(result.value) } : result;
}

function registrationResultFlowToWire(
  result: GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationFlow>,
): PMGoogleEmailOtpWalletAuthRegistrationWireResult {
  return result.ok ? { ok: true, value: flowToWire(result.value) } : result;
}

function stripRegistrationCompletionResult(
  result: GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>,
): GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted> {
  if (!result.ok) return result;
  return {
    ok: true,
    value: {
      walletId: result.value.walletId,
      mode: 'register',
      session: result.value.session,
    },
  };
}

function readFlowHandleId(value: unknown): string {
  return readRequiredString(recordFromPayload(value), 'flowHandleId');
}

function assertFlowHandleMatchesPayload(
  flow: GoogleEmailOtpWalletAuthFlow,
  payload: Record<string, unknown>,
): void {
  const flowId = readRequiredString(payload, 'flowId');
  const walletId = readRequiredString(payload, 'walletId');
  const mode = readRequiredString(payload, 'mode');
  if (flow.flowId !== flowId) {
    throw new Error('Google Email OTP wallet auth flow handle does not match flow id');
  }
  if (String(flow.walletId) !== walletId) {
    throw new Error('Google Email OTP wallet auth flow handle does not match wallet');
  }
  if (flow.mode !== mode) {
    throw new Error('Google Email OTP wallet auth flow handle does not match mode');
  }
}

function takeFlow(value: unknown): GoogleEmailOtpWalletAuthFlow {
  const payload = recordFromPayload(value);
  const flowHandleId = readFlowHandleId(payload);
  const record = googleEmailOtpWalletAuthFlows.get(flowHandleId);
  if (!record) {
    throw new Error('Google Email OTP wallet auth flow handle is not active');
  }
  if (Date.now() > record.expiresAtMs) {
    googleEmailOtpWalletAuthFlows.delete(flowHandleId);
    void record.flow.cancel().catch(() => undefined);
    throw new Error('Google Email OTP wallet auth flow handle expired');
  }
  assertFlowHandleMatchesPayload(record.flow, payload);
  return record.flow;
}

function burnFlow(value: unknown): GoogleEmailOtpWalletAuthFlow {
  const payload = recordFromPayload(value);
  const flowHandleId = readFlowHandleId(payload);
  const flow = takeFlow(value);
  googleEmailOtpWalletAuthFlows.delete(flowHandleId);
  return flow;
}

function parseGetEmailOtpRecoveryCodeStatusPayload(value: unknown): {
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
} {
  const record = recordFromPayload(value);
  const relayUrl = readOptionalString(record, 'relayUrl');
  const appSessionJwt = readOptionalString(record, 'appSessionJwt');
  return {
    walletId: readRequiredString(record, 'walletId'),
    ...(relayUrl ? { relayUrl } : {}),
    ...(appSessionJwt ? { appSessionJwt } : {}),
  };
}

async function showEmailOtpRecoveryCodesInIframe(input: {
  pm: ReturnType<HandlerDeps['getSeamsWeb']>;
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}) {
  const status = await input.pm.recovery.getEmailOtpRecoveryCodeStatus({
    walletId: input.walletId,
    ...(input.relayUrl ? { relayUrl: input.relayUrl } : {}),
    ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
  });
  if (!status.enrollmentId || !status.enrollmentSealKeyVersion) {
    return { status, displayedStoredCodes: false };
  }
  const backup = await emailOtpRecoveryCodeBackupRepository.readMatching({
    walletId: status.walletId,
    enrollmentId: status.enrollmentId,
    enrollmentSealKeyVersion: status.enrollmentSealKeyVersion,
  });
  if (!backup) return { status, displayedStoredCodes: false };
  const displayed =
    (await emailOtpRecoveryCodeBackupRepository
      .markDisplayed({
        walletId: backup.walletId,
        enrollmentId: backup.enrollmentId,
        enrollmentSealKeyVersion: backup.enrollmentSealKeyVersion,
      })
      .catch(() => null)) || backup;
  await new Promise<void>((resolve) => {
    showEmailOtpRecoveryCodeBackupUi(
      {
        walletId: displayed.walletId,
        enrollmentId: displayed.enrollmentId,
        enrollmentSealKeyVersion: displayed.enrollmentSealKeyVersion,
        recoveryCodesIssuedAtMs: displayed.recoveryCodesIssuedAtMs,
        recoveryKeys: displayed.recoveryKeys,
      },
      {
        onDownloaded: async () => {
          await emailOtpRecoveryCodeBackupRepository.markDownloaded({
            walletId: displayed.walletId,
            enrollmentId: displayed.enrollmentId,
            enrollmentSealKeyVersion: displayed.enrollmentSealKeyVersion,
          });
        },
        onClosed: resolve,
      },
    );
  });
  return { status, displayedStoredCodes: true };
}

async function storeEmailOtpRecoveryCodeBackupInIframe(input: {
  pm: ReturnType<HandlerDeps['getSeamsWeb']>;
  result: EmailOtpEnrollmentResult;
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}) {
  return await backupEmailOtpRecoveryCodes({
    relayUrl: String(input.relayUrl || '').trim(),
    walletId: input.walletId,
    enrollment: input.result,
    storageScope: 'iframe_origin_indexeddb',
    ...(input.relayUrl ? { relayUrl: input.relayUrl } : {}),
    ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
  });
}

function enableEmailOtpUnlockDiagnosticsFromPayload(payload: Record<string, unknown>): void {
  const diagnostics = recordFromPayload(payload.diagnostics);
  Reflect.set(
    globalThis,
    '__SEAMS_EMAIL_OTP_UNLOCK_DIAGNOSTICS',
    diagnostics.emailOtpUnlockTimings === true,
  );
  delete payload.diagnostics;
}

export function createEmailOtpWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REQUEST_EMAIL_OTP_CHALLENGE: async (req: Req<'PM_REQUEST_EMAIL_OTP_CHALLENGE'>) => {
      const pm = deps.getSeamsWeb();
      const { walletId, relayUrl, appSessionJwt, operation } = req.payload!;
      const result = await pm.auth.requestEmailOtpChallenge({
        walletId,
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
      const { walletId, relayUrl, appSessionJwt } = req.payload!;
      const result = await pm.registration.requestEmailOtpEnrollmentChallenge({
        walletId,
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

    PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH: async (
      req: Req<'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payloadRecord = recordFromPayload(req.payload);
      enableEmailOtpUnlockDiagnosticsFromPayload(payloadRecord);
      if (payloadRecord.mode === 'register') {
        assertNoGoogleRegistrationOtpFields(payloadRecord);
      }
      const payload = withProgress(deps, req.requestId, payloadRecord);
      const result = await pm.auth.beginGoogleEmailOtpWalletAuth(
        payload as Parameters<typeof pm.auth.beginGoogleEmailOtpWalletAuth>[0],
      );
      respondOkResult(deps, req.requestId, resultFlowToWire(result));
    },

    PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND: async (
      req: Req<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND'>,
    ) => {
      const flow = takeFlow(req.payload);
      if (flow.mode !== 'login') {
        throw new Error('Google Email OTP wallet auth resend requires a login flow');
      }
      const result = await flow.resend();
      if (result.ok) {
        burnFlow(req.payload);
      }
      respondOkResult(deps, req.requestId, resultFlowToWire(result));
    },

    PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID: async (
      req: Req<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID'>,
    ) => {
      const flow = takeFlow(req.payload);
      if (flow.mode !== 'register') {
        throw new Error('Google Email OTP wallet auth reroll requires a registration flow');
      }
      assertNoGoogleRegistrationOtpFields(req.payload);
      const result = await flow.rerollWalletId();
      if (result.ok) {
        burnFlow(req.payload);
      }
      respondOkResult(deps, req.requestId, registrationResultFlowToWire(result));
    },

    PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT: async (
      req: Req<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT'>,
    ) => {
      const flow = takeFlow(req.payload);
      if (flow.mode !== 'login') {
        throw new Error('Google Email OTP wallet auth submit requires a login flow');
      }
      const payload = recordFromPayload(req.payload);
      const result: GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess> =
        await flow.submit({ otpCode: readRequiredString(payload, 'otpCode') });
      if (result.ok) {
        burnFlow(req.payload);
      }
      respondOkResult(deps, req.requestId, result);
    },

    PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION: async (
      req: Req<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION'>,
    ) => {
      const flow = takeFlow(req.payload);
      if (flow.mode !== 'register') {
        throw new Error('Google Email OTP wallet auth completion requires a registration flow');
      }
      assertNoGoogleRegistrationOtpFields(req.payload);
      const result = await flow.completeRegistration();
      if (result.ok) {
        burnFlow(req.payload);
      }
      respondOkResult(deps, req.requestId, stripRegistrationCompletionResult(result));
    },

    PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL: async (
      req: Req<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL'>,
    ) => {
      const flow = burnFlow(req.payload);
      await flow.cancel();
      respondOkResult(deps, req.requestId, undefined);
    },

    PM_ENROLL_EMAIL_OTP: async (req: Req<'PM_ENROLL_EMAIL_OTP'>) => {
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const payload = withProgress(deps, req.requestId, rawPayload);
      const result = await pm.registration.enrollEmailOtp(
        payload as Parameters<typeof pm.registration.enrollEmailOtp>[0],
      );
      if (!('recoveryKeys' in result)) {
        respondOkResult(deps, req.requestId, result);
        return;
      }
      const walletId = String(rawPayload.walletId || '').trim();
      if (!walletId) {
        throw new Error('PM_ENROLL_EMAIL_OTP requires walletId');
      }
      const backedUpEnrollment = await storeEmailOtpRecoveryCodeBackupInIframe({
        pm,
        result,
        walletId,
        relayUrl: typeof rawPayload.relayUrl === 'string' ? rawPayload.relayUrl : undefined,
        appSessionJwt:
          typeof rawPayload.appSessionJwt === 'string' ? rawPayload.appSessionJwt : undefined,
      });
      respondOkResult(deps, req.requestId, backedUpEnrollment);
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

    PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS: async (
      req: Req<'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.getEmailOtpRecoveryCodeStatus(
        parseGetEmailOtpRecoveryCodeStatusPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_SHOW_EMAIL_OTP_RECOVERY_CODES: async (
      req: Req<'PM_SHOW_EMAIL_OTP_RECOVERY_CODES'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payload = parseGetEmailOtpRecoveryCodeStatusPayload(req.payload);
      const result = await showEmailOtpRecoveryCodesInIframe({
        pm,
        walletId: payload.walletId,
        ...(payload.relayUrl ? { relayUrl: payload.relayUrl } : {}),
        ...(payload.appSessionJwt ? { appSessionJwt: payload.appSessionJwt } : {}),
      });
      respondOkResult(deps, req.requestId, result);
    },

    PM_ROTATE_EMAIL_OTP_RECOVERY_CODES: async (
      req: Req<'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.rotateEmailOtpRecoveryCodes(
        parseGetEmailOtpRecoveryCodeStatusPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY: async (
      req: Req<'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const payload = withProgress(deps, req.requestId, rawPayload);
      const result = await pm.registration.enrollAndLoginWithEmailOtpEcdsaCapability(
        payload as Parameters<typeof pm.registration.enrollAndLoginWithEmailOtpEcdsaCapability>[0],
      );
      if (!('recoveryKeys' in result.enrollment)) {
        respondOkResult(deps, req.requestId, result);
        return;
      }
      const backedUpEnrollment = await storeEmailOtpRecoveryCodeBackupInIframe({
        pm,
        result: result.enrollment,
        walletId: walletIdFromPayloadSession(rawPayload.walletSession),
        relayUrl: typeof rawPayload.relayUrl === 'string' ? rawPayload.relayUrl : undefined,
        appSessionJwt:
          typeof rawPayload.appSessionJwt === 'string' ? rawPayload.appSessionJwt : undefined,
      });
      respondOkResult(deps, req.requestId, {
        ...result,
        enrollment: backedUpEnrollment,
      });
    },
  };
}

import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOkResult, withProgress } from './shared';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type { WalletCustodyAdminOperation } from '@shared/authorization/walletCustodyOperation';
import type {
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from '@/SeamsWeb/signingSurface/types';
import type {
  PMGoogleEmailOtpWalletAuthRegistrationWireFlow,
  PMGoogleEmailOtpWalletAuthRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthWireFlow,
  PMGoogleEmailOtpWalletAuthWireResult,
} from '../../shared/messages';
import { redeemHostedWalletSeamsSession } from '../hostedWalletSeamsSession';

function recordFromPayload(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
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

function assertNoParentPostedWalletSessionToken(value: unknown): void {
  const record = recordFromPayload(value);
  if (Object.prototype.hasOwnProperty.call(record, 'walletSessionToken')) {
    throw new Error('wallet iframe requests must not carry walletSessionToken');
  }
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
  return secureRandomId('google-email-otp', 16, 'Google Email OTP wallet auth flow handles');
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
      registration: result.value.registration,
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

function parseWalletRecoverySessionPayload(value: unknown): { walletId: string } {
  const record = recordFromPayload(value);
  return { walletId: readRequiredString(record, 'walletId') };
}

function parseWalletCustodyEmailOtpChallengePayload(value: unknown): {
  walletId: string;
  providerSubjectId: string;
  operation: WalletCustodyAdminOperation;
  payload: Record<string, unknown>;
  requestOrigin?: string;
} {
  const record = recordFromPayload(value);
  const operation = readRequiredString(record, 'operation');
  if (
    operation !== 'credentials_list' &&
    operation !== 'credential_label' &&
    operation !== 'recovery_acknowledge' &&
    operation !== 'recovery_rotate' &&
    operation !== 'recovery_read'
  ) {
    throw new Error('Wallet custody Email OTP challenge operation is invalid');
  }
  const payload = recordFromPayload(record.payload);
  if (Object.keys(payload).length === 0 && record.payload === undefined) {
    throw new Error('Wallet custody Email OTP challenge payload is required');
  }
  return {
    walletId: readRequiredString(record, 'walletId'),
    providerSubjectId: readRequiredString(record, 'providerSubjectId'),
    operation,
    payload,
    ...(readOptionalString(record, 'requestOrigin')
      ? { requestOrigin: readOptionalString(record, 'requestOrigin') }
      : {}),
  };
}

function parseWalletRecoveryRotationPayload(value: unknown): {
  walletId: string;
  authorization:
    | { kind: 'existing_passkey' }
    | {
        kind: 'email_otp';
        providerSubjectId: string;
        challengeId: string;
        challenge_digest: string;
        otpCode: string;
      };
} {
  const record = recordFromPayload(value);
  const authorization = recordFromPayload(record.authorization);
  if (authorization.kind === 'existing_passkey') {
    return {
      walletId: readRequiredString(record, 'walletId'),
      authorization: { kind: 'existing_passkey' },
    };
  }
  if (authorization.kind === 'email_otp') {
    return {
      walletId: readRequiredString(record, 'walletId'),
      authorization: {
        kind: 'email_otp',
        providerSubjectId: readRequiredString(authorization, 'providerSubjectId'),
        challengeId: readRequiredString(authorization, 'challengeId'),
        challenge_digest: readRequiredString(authorization, 'challenge_digest'),
        otpCode: readRequiredString(authorization, 'otpCode'),
      },
    };
  }
  throw new Error('Wallet recovery rotation authorization is invalid');
}

function enableEmailOtpDiagnosticsFromPayload(payload: Record<string, unknown>): void {
  const diagnostics = recordFromPayload(payload.diagnostics);
  Reflect.set(
    globalThis,
    '__SEAMS_EMAIL_OTP_UNLOCK_DIAGNOSTICS',
    diagnostics.emailOtpUnlockTimings === true,
  );
  Reflect.set(
    globalThis,
    '__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS',
    diagnostics.registrationBenchmarkTimings === true,
  );
  delete payload.diagnostics;
}

export function createEmailOtpWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION: async (
      req: Req<'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION'>,
    ) => {
      const session = await redeemHostedWalletSeamsSession(req.payload, req.payload!.relayUrl);
      respondOkResult(deps, req.requestId, {
        kind: 'redeemed_hosted_wallet_seams_session',
        expiresAtMs: session.expiresAtMs,
      });
    },

    PM_REQUEST_EMAIL_OTP_CHALLENGE: async (req: Req<'PM_REQUEST_EMAIL_OTP_CHALLENGE'>) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const { walletId, relayUrl, operation } = req.payload!;
      const result = await pm.auth.requestEmailOtpChallenge({
        walletId,
        ...(relayUrl ? { relayUrl } : {}),
        ...(operation ? { operation } : {}),
      });
      respondOkResult(deps, req.requestId, result);
    },

    PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE: async (
      req: Req<'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE'>,
    ) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const { walletId, relayUrl } = req.payload!;
      const result = await pm.registration.requestEmailOtpEnrollmentChallenge({
        walletId,
        ...(relayUrl ? { relayUrl } : {}),
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

    PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH: async (
      req: Req<'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'>,
    ) => {
      const pm = deps.getSeamsWeb();
      const payloadRecord = recordFromPayload(req.payload);
      enableEmailOtpDiagnosticsFromPayload(payloadRecord);
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
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const walletId = String(rawPayload.walletId || '').trim();
      if (!walletId) {
        throw new Error('PM_ENROLL_EMAIL_OTP requires walletId');
      }
      const payload = withProgress(deps, req.requestId, {
        ...rawPayload,
      });
      const result = await pm.registration.enrollEmailOtp(
        payload as Parameters<typeof pm.registration.enrollEmailOtp>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY: async (
      req: Req<'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'>,
    ) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const walletId = String(req.payload?.walletSession.walletId || '').trim();
      if (!walletId) {
        throw new Error('PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY requires walletId');
      }
      const payload = withProgress(deps, req.requestId, {
        ...(req.payload || {}),
      });
      const result = await pm.auth.loginWithEmailOtpEcdsaCapability(
        payload as Parameters<typeof pm.auth.loginWithEmailOtpEcdsaCapability>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_REFRESH_EMAIL_OTP_SIGNING_SESSION: async (
      req: Req<'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'>,
    ) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const payload = withProgress(deps, req.requestId, req.payload || {});
      const result = await pm.auth.refreshEmailOtpSigningSession(
        payload as Parameters<typeof pm.auth.refreshEmailOtpSigningSession>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_WALLET_RECOVERY_CODE_STATUS: async (req: Req<'PM_GET_WALLET_RECOVERY_CODE_STATUS'>) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.getWalletRecoveryCodeStatus(
        parseWalletRecoverySessionPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_REQUEST_WALLET_CUSTODY_EMAIL_OTP_CHALLENGE: async (
      req: Req<'PM_REQUEST_WALLET_CUSTODY_EMAIL_OTP_CHALLENGE'>,
    ) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.requestWalletCustodyEmailOtpChallenge(
        parseWalletCustodyEmailOtpChallengePayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP: async (
      req: Req<'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP'>,
    ) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.acknowledgeWalletRecoveryCodeBackup(
        parseWalletRecoverySessionPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_ROTATE_WALLET_RECOVERY_CODES: async (req: Req<'PM_ROTATE_WALLET_RECOVERY_CODES'>) => {
      assertNoParentPostedWalletSessionToken(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.rotateWalletRecoveryCodes(
        parseWalletRecoveryRotationPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },
  };
}

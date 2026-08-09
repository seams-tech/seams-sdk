import type { HandlerDeps, HandlerMap, Req } from './walletIframeHandler.types';
import { respondOkResult, withProgress } from './shared';
import { secureRandomId } from '@shared/utils/secureRandomId';
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
} from '../../../operations/authMethods/emailOtp/recoveryCodeBackup';
import type {
  PMGoogleEmailOtpWalletAuthRegistrationWireFlow,
  PMGoogleEmailOtpWalletAuthRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthWireFlow,
  PMGoogleEmailOtpWalletAuthWireResult,
} from '../../shared/messages';
import {
  activeWalletOrHostedAppSessionJwt,
  canonicalRelayUrl,
  redeemHostedWalletSeamsSession,
} from '../hostedWalletSeamsSession';

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

function assertNoParentPostedAppSessionJwt(value: unknown): void {
  const record = recordFromPayload(value);
  if (Object.prototype.hasOwnProperty.call(record, 'appSessionJwt')) {
    throw new Error('wallet iframe requests must not carry appSessionJwt');
  }
}

function requireWalletRelayUrl(value: string | undefined, expectedRelayUrl: string): string {
  const expected = canonicalRelayUrl(expectedRelayUrl);
  const requested = canonicalRelayUrl(value || expectedRelayUrl);
  if (requested !== expected) {
    throw new Error('wallet recovery relay URL does not match the wallet origin');
  }
  return expected;
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

function parseWalletRecoverySessionPayload(
  value: unknown,
): { walletId: string } {
  const record = recordFromPayload(value);
  return { walletId: readRequiredString(record, 'walletId') };
}

function parseWalletRecoveryBootstrapChallengePayload(
  value: unknown,
  expectedRelayUrl: string,
): { walletId: string; orgId: string; relayUrl?: string } {
  const record = recordFromPayload(value);
  return {
    walletId: readRequiredString(record, 'walletId'),
    orgId: readRequiredString(record, 'orgId'),
    relayUrl: requireWalletRelayUrl(readOptionalString(record, 'relayUrl'), expectedRelayUrl),
  };
}

function parseWalletRecoveryBootstrapVerifyPayload(
  value: unknown,
  expectedRelayUrl: string,
): {
  walletId: string;
  orgId: string;
  challengeId: string;
  otpCode: string;
  relayUrl?: string;
} {
  const record = recordFromPayload(value);
  return {
    walletId: readRequiredString(record, 'walletId'),
    orgId: readRequiredString(record, 'orgId'),
    challengeId: readRequiredString(record, 'challengeId'),
    otpCode: readRequiredString(record, 'otpCode'),
    relayUrl: requireWalletRelayUrl(readOptionalString(record, 'relayUrl'), expectedRelayUrl),
  };
}

function parsePrepareWalletRecoveryWithBootstrapPayload(
  value: unknown,
  expectedRelayUrl: string,
): {
  walletId: string;
  orgId: string;
  challengeId: string;
  recoveryBootstrapGrant: string;
  replacedCredentialIdB64u: string;
  recoveryCode: string;
  relayUrl?: string;
} {
  const record = recordFromPayload(value);
  return {
    walletId: readRequiredString(record, 'walletId'),
    orgId: readRequiredString(record, 'orgId'),
    challengeId: readRequiredString(record, 'challengeId'),
    recoveryBootstrapGrant: readRequiredString(record, 'recoveryBootstrapGrant'),
    replacedCredentialIdB64u: readRequiredString(record, 'replacedCredentialIdB64u'),
    recoveryCode: readRequiredString(record, 'recoveryCode'),
    relayUrl: requireWalletRelayUrl(readOptionalString(record, 'relayUrl'), expectedRelayUrl),
  };
}

function parseCompleteWalletRecoveryPayload(
  value: unknown,
  expectedRelayUrl: string,
): {
  walletId: string;
  recoveryOperationId: string;
  relayUrl?: string;
  appSessionJwt?: string;
} {
  const record = recordFromPayload(value);
  const relayUrl = requireWalletRelayUrl(readOptionalString(record, 'relayUrl'), expectedRelayUrl);
  const walletId = readRequiredString(record, 'walletId');
  const appSessionJwt = activeWalletOrHostedAppSessionJwt(relayUrl, walletId);
  return {
    walletId,
    recoveryOperationId: readRequiredString(record, 'recoveryOperationId'),
    relayUrl,
    ...(appSessionJwt ? { appSessionJwt } : {}),
  };
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
      const pm = deps.getSeamsWeb();
      const session = await redeemHostedWalletSeamsSession(
        req.payload,
        req.payload!.relayUrl,
      );
      respondOkResult(deps, req.requestId, {
        kind: 'redeemed_hosted_wallet_seams_session',
        expiresAtMs: session.expiresAtMs,
      });
    },

    PM_REQUEST_EMAIL_OTP_CHALLENGE: async (req: Req<'PM_REQUEST_EMAIL_OTP_CHALLENGE'>) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const { walletId, relayUrl, operation } = req.payload!;
      const appSessionJwt = activeWalletOrHostedAppSessionJwt(
        relayUrl || pm.configs.network.relayer.url,
        walletId,
      );
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
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const { walletId, relayUrl } = req.payload!;
      const appSessionJwt = activeWalletOrHostedAppSessionJwt(
        relayUrl || pm.configs.network.relayer.url,
        walletId,
      );
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
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const rawPayload = recordFromPayload(req.payload);
      const walletId = String(rawPayload.walletId || '').trim();
      if (!walletId) {
        throw new Error('PM_ENROLL_EMAIL_OTP requires walletId');
      }
      const appSessionJwt = activeWalletOrHostedAppSessionJwt(
        typeof rawPayload.relayUrl === 'string'
          ? rawPayload.relayUrl
          : pm.configs.network.relayer.url,
        walletId,
      );
      const payload = withProgress(deps, req.requestId, {
        ...rawPayload,
        ...(appSessionJwt ? { appSessionJwt } : {}),
      });
      const result = await pm.registration.enrollEmailOtp(
        payload as Parameters<typeof pm.registration.enrollEmailOtp>[0],
      );
      if (!('recoveryKeys' in result)) {
        respondOkResult(deps, req.requestId, result);
        return;
      }
      const backedUpEnrollment = await storeEmailOtpRecoveryCodeBackupInIframe({
        pm,
        result,
        walletId,
        relayUrl: typeof rawPayload.relayUrl === 'string' ? rawPayload.relayUrl : undefined,
        ...(appSessionJwt ? { appSessionJwt } : {}),
      });
      respondOkResult(deps, req.requestId, backedUpEnrollment);
    },

    PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY: async (
      req: Req<'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const walletId = String(req.payload?.walletSession.walletId || '').trim();
      if (!walletId) {
        throw new Error('PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY requires walletId');
      }
      const appSessionJwt = activeWalletOrHostedAppSessionJwt(
        req.payload?.relayUrl || pm.configs.network.relayer.url,
        walletId,
      );
      const payload = withProgress(deps, req.requestId, {
        ...(req.payload || {}),
        ...(appSessionJwt ? { appSessionJwt } : {}),
      });
      const result = await pm.auth.loginWithEmailOtpEcdsaCapability(
        payload as Parameters<typeof pm.auth.loginWithEmailOtpEcdsaCapability>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_REFRESH_EMAIL_OTP_SIGNING_SESSION: async (
      req: Req<'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const payload = withProgress(deps, req.requestId, req.payload || {});
      const result = await pm.auth.refreshEmailOtpSigningSession(
        payload as Parameters<typeof pm.auth.refreshEmailOtpSigningSession>[0],
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_GET_WALLET_RECOVERY_CODE_STATUS: async (
      req: Req<'PM_GET_WALLET_RECOVERY_CODE_STATUS'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.getWalletRecoveryCodeStatus(
        parseWalletRecoverySessionPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP: async (
      req: Req<'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.acknowledgeWalletRecoveryCodeBackup(
        parseWalletRecoverySessionPayload(req.payload),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_REQUEST_WALLET_RECOVERY_BOOTSTRAP_CHALLENGE: async (
      req: Req<'PM_REQUEST_WALLET_RECOVERY_BOOTSTRAP_CHALLENGE'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.requestWalletRecoveryBootstrapChallenge(
        parseWalletRecoveryBootstrapChallengePayload(req.payload, pm.configs.network.relayer.url),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_VERIFY_WALLET_RECOVERY_BOOTSTRAP: async (
      req: Req<'PM_VERIFY_WALLET_RECOVERY_BOOTSTRAP'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.verifyWalletRecoveryBootstrap(
        parseWalletRecoveryBootstrapVerifyPayload(req.payload, pm.configs.network.relayer.url),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_PREPARE_WALLET_RECOVERY_WITH_BOOTSTRAP: async (
      req: Req<'PM_PREPARE_WALLET_RECOVERY_WITH_BOOTSTRAP'>,
    ) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.prepareWalletRecoveryWithBootstrap(
        parsePrepareWalletRecoveryWithBootstrapPayload(
          req.payload,
          pm.configs.network.relayer.url,
        ),
      );
      respondOkResult(deps, req.requestId, result);
    },

    PM_COMPLETE_WALLET_RECOVERY: async (req: Req<'PM_COMPLETE_WALLET_RECOVERY'>) => {
      assertNoParentPostedAppSessionJwt(req.payload);
      const pm = deps.getSeamsWeb();
      const result = await pm.recovery.completeWalletRecovery(
        parseCompleteWalletRecoveryPayload(req.payload, pm.configs.network.relayer.url),
      );
      respondOkResult(deps, req.requestId, result);
    },
  };
}

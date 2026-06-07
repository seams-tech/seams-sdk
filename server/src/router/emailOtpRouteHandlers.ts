import { toOptionalRecordString } from '@shared/utils/validation';
import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_EXPORT_OPERATION } from '@shared/utils/emailOtpDomain';
import type { AuthService } from '../core/AuthService';
import type { RelayRouterOptions } from './relay';
import {
  authorizeEmailOtpExportPolicy,
  emailOtpExportDeniedDecisionFromResult,
  emailOtpExportPolicyWebhookEventDescriptor,
} from './emailOtpExportPolicy';
import { parseWalletEmailOtpLoginOperation } from './emailOtpRequestValidation';
import {
  emailOtpChallengeResponseBody,
  emailOtpEnrollmentFinalizeResponseBody,
  emailOtpEnrolledWebhookEventDescriptor,
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoginVerifyResponseBody,
  emailOtpResultStatus,
  emailOtpServerSealResponseBody,
  emailOtpStatusCode,
  getSessionWalletId,
  hashEmailOtpAppSessionClaims,
  isGoogleOidcEmailOtpSession,
  validateEmailOtpChannel,
  validateEmailOtpJsonObjectBody,
  validateEmailOtpRequiredString,
  validateEmailOtpWalletId,
  type EmailOtpWebhookEventDescriptor,
} from './emailOtpSessionRouteHelpers';

export type EmailOtpRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type EmitEmailOtpRouteWebhook = (input: {
  descriptor: EmailOtpWebhookEventDescriptor;
  claims?: Record<string, unknown> | null;
  userId: string;
  walletId?: string;
}) => Promise<void>;

async function requireEmailOtpEnrollmentMutationAuth(input: {
  service: AuthService;
  claims: Record<string, unknown>;
  walletId: string;
}): Promise<EmailOtpRouteResponse | null> {
  if (isGoogleOidcEmailOtpSession(input.claims)) return null;

  const strongAuthGate = await input.service.isEmailOtpStrongAuthRequired({
    walletId: input.walletId,
  });
  if (!strongAuthGate.ok) {
    return { status: emailOtpStatusCode(strongAuthGate.code), body: strongAuthGate };
  }
  if (!strongAuthGate.required) return null;

  return {
    status: 403,
    body: {
      ok: false,
      code: 'stronger_auth_required',
      message: 'Passkey authentication is required before modifying Email OTP enrollment',
      ...(strongAuthGate.lastEmailOtpLoginAtMs
        ? { lastEmailOtpLoginAtMs: strongAuthGate.lastEmailOtpLoginAtMs }
        : {}),
      ...(strongAuthGate.lastStrongAuthAtMs
        ? { lastStrongAuthAtMs: strongAuthGate.lastStrongAuthAtMs }
        : {}),
    },
  };
}

function resolveEmailOtpProviderUserId(input: {
  claims: Record<string, unknown>;
  userId: string;
}):
  | { ok: true; providerUserId: string }
  | { ok: false; response: EmailOtpRouteResponse } {
  if (!isGoogleOidcEmailOtpSession(input.claims)) {
    return { ok: true, providerUserId: input.userId };
  }
  const providerSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (!providerSubject) {
    return {
      ok: false,
      response: {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_app_session',
          message: 'Google Email OTP session requires providerSubject',
        },
      },
    };
  }
  return { ok: true, providerUserId: providerSubject };
}

export async function handleEmailOtpRegistrationChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const email =
    typeof input.claims.email === 'string' ? input.claims.email.trim().toLowerCase() : '';
  const googleRegistrationSession = isGoogleOidcEmailOtpSession(input.claims);
  const claimProviderSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (googleRegistrationSession && !claimProviderSubject) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_app_session',
        message: 'Google Email OTP registration requires providerSubject',
      },
    };
  }
  const challengeSubjectId = googleRegistrationSession ? claimProviderSubject : input.userId;
  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.createEmailOtpEnrollmentChallenge({
    userId: challengeSubjectId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    email,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpRegistrationSealRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const wrappedCiphertextValidation = validateEmailOtpRequiredString(body, 'wrappedCiphertext');
  if (!wrappedCiphertextValidation.ok) {
    return {
      status: wrappedCiphertextValidation.status,
      body: wrappedCiphertextValidation.body,
    };
  }

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const result = await input.service.applyEmailOtpServerSeal({
    wrappedCiphertext: wrappedCiphertextValidation.value,
  });
  return {
    status: emailOtpResultStatus(result),
    body: emailOtpServerSealResponseBody(result, walletId),
  };
}

export async function handleEmailOtpRegistrationFinalizeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const authGate = await requireEmailOtpEnrollmentMutationAuth({
    service: input.service,
    claims: input.claims,
    walletId,
  });
  if (authGate) return authGate;

  const googleRegistrationSession = isGoogleOidcEmailOtpSession(input.claims);
  const claimProviderSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (googleRegistrationSession && !claimProviderSubject) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_app_session',
        message: 'Google Email OTP registration requires providerSubject',
      },
    };
  }
  const providerSubject = googleRegistrationSession ? claimProviderSubject : input.userId;
  const proofEmail = toOptionalRecordString(input.claims, 'email')?.toLowerCase();
  const bodyGoogleEmailOtpRegistrationAttemptId = toOptionalRecordString(
    body,
    'googleEmailOtpRegistrationAttemptId',
  );
  const claimGoogleEmailOtpRegistrationAttemptId = googleRegistrationSession
    ? toOptionalRecordString(input.claims, 'googleEmailOtpRegistrationAttemptId')
    : undefined;
  const googleEmailOtpRegistrationAttemptId =
    bodyGoogleEmailOtpRegistrationAttemptId || claimGoogleEmailOtpRegistrationAttemptId;
  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.verifyEmailOtpEnrollment({
    providerSubject,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    ...(proofEmail ? { proofEmail } : {}),
    clientIp: input.clientIp,
    recoveryWrappedEnrollmentEscrows: body.recoveryWrappedEnrollmentEscrows,
    enrollmentSealKeyVersion: body.enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u: body.clientUnlockPublicKeyB64u,
    unlockKeyVersion: body.unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u: body.thresholdEcdsaClientVerifyingShareB64u,
    ...(googleEmailOtpRegistrationAttemptId ? { googleEmailOtpRegistrationAttemptId } : {}),
  });

  if (result.ok) {
    await input.emitWebhook({
      descriptor: emailOtpEnrolledWebhookEventDescriptor({
        challengeId,
        otpChannel: result.otpChannel,
        enrollmentSealKeyVersion: result.enrollment.enrollmentSealKeyVersion,
        unlockKeyVersion: result.enrollment.unlockKeyVersion,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId: result.walletId,
    });
  } else {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'registration_finalize',
      code: result.code,
      message: result.message,
      challengeId,
      otpChannel,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpEnrollmentFinalizeResponseBody(result),
  };
}

export async function handleEmailOtpLoginChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
  opts: RelayRouterOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'challenge',
          userId: input.userId,
          walletId,
          orgId: readEmailOtpOrgIdFromClaims(input.claims),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_challenge',
        decision: exportPolicy,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
    };
  }

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    providerUserId: providerUser.providerUserId,
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const result = await input.service.createEmailOtpChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    email: email.email,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (!result.ok && result.code === 'otp_locked_out') {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'login_challenge',
      code: result.code,
      message: result.message,
      otpChannel,
      operation: parsedOperation.operation,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  if (result.ok && exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_challenge_issued',
        source: 'login_challenge',
        decision: exportPolicy,
        challengeId: result.challenge.challengeId,
        otpChannel,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpDeviceRecoveryChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    providerUserId: providerUser.providerUserId,
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.createEmailOtpDeviceRecoveryChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    email: email.email,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpRecoveryWrappedEscrowsRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;
  const result = await input.service.verifyEmailOtpDeviceRecoveryChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });

  if (!result.ok) {
    return { status: emailOtpStatusCode(result.code), body: result };
  }

  return {
    status: 200,
    body: {
      ok: true,
      challengeId: result.challengeId,
      otpChannel: result.otpChannel,
      recoveryConsumeGrant: result.recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs: result.recoveryConsumeGrantExpiresAtMs,
      enrollment: result.enrollment,
      recoveryWrappedEnrollmentEscrows: result.recoveryWrappedEnrollmentEscrows,
    },
  };
}

export async function handleEmailOtpRecoveryKeyConsumeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };

  for (const field of [
    'recoveryKey',
    'recoveryKeys',
    'recoveryKeyB64u',
    'recoveryKek',
    'encS',
    'encSB64u',
    'S',
    'emailOtpSecretS',
  ]) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-key consume requests must not include recovery-key material',
        },
      };
    }
  }

  const recoveryKeyIdValidation = validateEmailOtpRequiredString(body, 'recoveryKeyId');
  if (!recoveryKeyIdValidation.ok) {
    return { status: recoveryKeyIdValidation.status, body: recoveryKeyIdValidation.body };
  }
  const recoveryConsumeGrantValidation = validateEmailOtpRequiredString(
    body,
    'recoveryConsumeGrant',
  );
  if (!recoveryConsumeGrantValidation.ok) {
    return {
      status: recoveryConsumeGrantValidation.status,
      body: recoveryConsumeGrantValidation.body,
    };
  }

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.consumeEmailOtpRecoveryKey({
    recoveryConsumeGrant: recoveryConsumeGrantValidation.value,
    userId: input.userId,
    walletId: walletValidation.walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    recoveryKeyId: recoveryKeyIdValidation.value,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  return { status: emailOtpResultStatus(result), body: result };
}

export async function handleEmailOtpRecoveryKeyStatusRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const walletValidation = validateEmailOtpWalletId({
    body: bodyValidation.body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };

  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const result = await input.service.getEmailOtpRecoveryCodeStatus({
    userId: providerUser.providerUserId,
    walletId: walletValidation.walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  return { status: emailOtpResultStatus(result), body: result };
}

export async function handleEmailOtpRecoveryKeyRotateRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  for (const field of [
    'recoveryKey',
    'recoveryKeys',
    'recoveryKeyB64u',
    'recoveryKek',
    'encS',
    'encSB64u',
    'S',
    'emailOtpSecretS',
  ]) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-code rotation requests must not include recovery-code material',
        },
      };
    }
  }

  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };

  const result = await input.service.rotateEmailOtpRecoveryKeys({
    userId: input.userId,
    walletId: walletValidation.walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    enrollmentId: body.enrollmentId,
    enrollmentSealKeyVersion: body.enrollmentSealKeyVersion,
    recoveryWrappedEnrollmentEscrows: body.recoveryWrappedEnrollmentEscrows,
  });
  return { status: emailOtpResultStatus(result), body: result };
}

export async function handleEmailOtpRecoveryKeyAttemptFailedRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  for (const field of ['recoveryKey', 'recoveryKeyB64u', 'recoveryKek', 'encS', 'encSB64u']) {
    if (Object.prototype.hasOwnProperty.call(body, field)) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: 'Recovery-key failure reports must not include recovery-key material',
        },
      };
    }
  }

  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };

  const recoveryConsumeGrantValidation = validateEmailOtpRequiredString(
    body,
    'recoveryConsumeGrant',
  );
  if (!recoveryConsumeGrantValidation.ok) {
    return {
      status: recoveryConsumeGrantValidation.status,
      body: recoveryConsumeGrantValidation.body,
    };
  }

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const result = await input.service.recordEmailOtpRecoveryKeyAttemptFailure({
    recoveryConsumeGrant: recoveryConsumeGrantValidation.value,
    userId: input.userId,
    walletId: walletValidation.walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  return { status: emailOtpResultStatus(result), body: result };
}

function validateSigningSessionWalletId(input: {
  body: Record<string, unknown>;
  userId: string;
}): { ok: true; walletId: string } | { ok: false; response: EmailOtpRouteResponse } {
  const walletId = String(input.body.walletId || '').trim();
  if (!walletId) {
    return {
      ok: false,
      response: {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: 'walletId is required' },
      },
    };
  }
  if (walletId !== String(input.userId || '').trim()) {
    return {
      ok: false,
      response: {
        status: 403,
        body: {
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'walletId must match the restored signing-session wallet',
        },
      },
    };
  }
  return { ok: true, walletId };
}

function readEmailOtpOrgIdFromClaims(claims: Record<string, unknown>): string {
  const directOrgId = toOptionalRecordString(claims, 'orgId');
  if (directOrgId) return directOrgId;
  const runtimePolicyScope =
    claims.runtimePolicyScope && typeof claims.runtimePolicyScope === 'object'
      ? (claims.runtimePolicyScope as Record<string, unknown>)
      : null;
  return runtimePolicyScope ? toOptionalRecordString(runtimePolicyScope, 'orgId') || '' : '';
}

async function readServerKnownEmailOtpAddress(input: {
  service: AuthService;
  walletId: string;
  orgId?: string;
  providerUserId?: string;
}): Promise<
  | { ok: true; email: string; orgId: string }
  | { ok: false; status: number; body: Record<string, unknown> }
> {
  const orgId = String(input.orgId || '').trim();
  if (!orgId) {
    return {
      ok: false,
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Missing orgId' },
    };
  }
  const enrollment = await input.service.readActiveEmailOtpEnrollment({
    walletId: input.walletId,
    orgId,
    providerUserId: input.providerUserId,
  });
  if (!enrollment.ok) {
    return { ok: false, status: emailOtpStatusCode(enrollment.code), body: enrollment };
  }
  if (enrollment.enrollment.walletId !== input.walletId || enrollment.enrollment.orgId !== orgId) {
    return {
      ok: false,
      status: 403,
      body: {
        ok: false,
        code: 'forbidden',
        message: 'Email OTP enrollment does not match the requested wallet',
      },
    };
  }

  return {
    ok: true,
    email: enrollment.enrollment.verifiedEmail,
    orgId: enrollment.enrollment.orgId,
  };
}

export async function handleEmailOtpSigningSessionChallengeRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  sessionHash: string;
  clientIp?: string;
  service: AuthService;
  opts: RelayRouterOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateSigningSessionWalletId({ body, userId: input.userId });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'challenge',
          userId: input.userId,
          walletId,
          ...(email.orgId ? { orgId: email.orgId } : {}),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_challenge',
        decision: exportPolicy,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: { ok: false, code: exportPolicy.code, message: exportPolicy.message },
    };
  }

  const result = await input.service.createEmailOtpChallenge({
    userId: input.userId,
    walletId,
    ...(email.orgId ? { orgId: email.orgId } : {}),
    email: email.email,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (!result.ok && result.code === 'otp_locked_out') {
    for (const descriptor of emailOtpFailureWebhookEventDescriptors({
      source: 'signing_session_challenge',
      code: result.code,
      message: result.message,
      otpChannel,
      operation: parsedOperation.operation,
      lockedUntilMs:
        typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
          ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
          : undefined,
    })) {
      await input.emitWebhook({
        descriptor,
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
  }

  if (result.ok && exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_challenge_issued',
        source: 'signing_session_challenge',
        decision: exportPolicy,
        challengeId: result.challenge.challengeId,
        otpChannel,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return {
    status: emailOtpResultStatus(result),
    body: emailOtpChallengeResponseBody(result),
  };
}

export async function handleEmailOtpLoginVerifyRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
  opts: RelayRouterOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateEmailOtpWalletId({
    body,
    claims: input.claims,
    userId: input.userId,
  });
  if (!walletValidation.ok) return { status: walletValidation.status, body: walletValidation.body };
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'verify',
          userId: input.userId,
          walletId,
          orgId: readEmailOtpOrgIdFromClaims(input.claims),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          challengeId,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_verify',
        decision: exportPolicy,
        challengeId,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: {
        ok: false,
        code: exportPolicy.code,
        message: exportPolicy.message,
      },
    };
  }

  const result = await input.service.verifyEmailOtpChallenge({
    userId: providerUser.providerUserId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (result.ok) {
    if (exportPolicy) {
      await input.emitWebhook({
        descriptor: emailOtpExportPolicyWebhookEventDescriptor({
          eventType: 'wallet.email_otp.export_approved',
          source: 'login_verify',
          decision: exportPolicy,
          challengeId: result.challengeId,
          otpChannel,
        }),
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
    const enrollment = await input.service.readEmailOtpEnrollment({
      walletId,
      orgId: readEmailOtpOrgIdFromClaims(input.claims),
    });
    if (!enrollment.ok) {
      return { status: emailOtpStatusCode(enrollment.code), body: enrollment };
    }
    return {
      status: 200,
      body: emailOtpLoginVerifyResponseBody({ result, enrollment }),
    };
  }

  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'login_verify',
    code: result.code,
    message: result.message,
    challengeId,
    otpChannel,
    operation: parsedOperation.operation,
    lockedUntilMs:
      typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
        ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
        : undefined,
  })) {
    await input.emitWebhook({
      descriptor,
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  if (exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'login_verify',
        decision: emailOtpExportDeniedDecisionFromResult({
          code: result.code,
          message: result.message,
          policySource: exportPolicy.policySource,
          ...(exportPolicy.policyId ? { policyId: exportPolicy.policyId } : {}),
          ...(exportPolicy.approvalId ? { approvalId: exportPolicy.approvalId } : {}),
        }),
        challengeId,
        otpChannel,
        code: result.code,
        message: result.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return { status: emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpLoginVerifyAndUnsealRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
  opts: RelayRouterOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const wrappedCiphertextValidation = validateEmailOtpRequiredString(body, 'wrappedCiphertext');
  if (!wrappedCiphertextValidation.ok) {
    return {
      status: wrappedCiphertextValidation.status,
      body: wrappedCiphertextValidation.body,
    };
  }

  const verified = await handleEmailOtpLoginVerifyRoute(input);
  if (verified.status !== 200 || verified.body.ok !== true) return verified;

  const loginGrant = String(verified.body.loginGrant || '').trim();
  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const sessionWalletId = getSessionWalletId(input.claims, input.userId);
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;
  const grant = await input.service.consumeEmailOtpGrant({
    loginGrant,
    userId: providerUser.providerUserId,
    walletId: sessionWalletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  if (!grant.ok) return { status: emailOtpStatusCode(grant.code), body: grant };

  const unsealed = await input.service.removeEmailOtpServerSeal({
    wrappedCiphertext: wrappedCiphertextValidation.value,
  });
  if (!unsealed.ok) return { status: emailOtpStatusCode(unsealed.code), body: unsealed };

  return {
    status: 200,
    body: {
      ok: true,
      challengeId: verified.body.challengeId,
      ciphertext: unsealed.ciphertext,
      otpChannel: verified.body.otpChannel,
      enrollmentSealKeyVersion: unsealed.enrollmentSealKeyVersion,
    },
  };
}

export async function handleEmailOtpSigningSessionVerifyRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  sessionHash: string;
  clientIp?: string;
  service: AuthService;
  opts: RelayRouterOptions;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateSigningSessionWalletId({ body, userId: input.userId });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const challengeIdValidation = validateEmailOtpRequiredString(body, 'challengeId');
  if (!challengeIdValidation.ok) {
    return { status: challengeIdValidation.status, body: challengeIdValidation.body };
  }
  const challengeId = challengeIdValidation.value;

  const otpCodeValidation = validateEmailOtpRequiredString(body, 'otpCode');
  if (!otpCodeValidation.ok) {
    return { status: otpCodeValidation.status, body: otpCodeValidation.body };
  }
  const otpCode = otpCodeValidation.value;

  const channelValidation = validateEmailOtpChannel(body);
  if (!channelValidation.ok)
    return { status: channelValidation.status, body: channelValidation.body };
  const otpChannel = channelValidation.otpChannel;

  const parsedOperation = parseWalletEmailOtpLoginOperation(body.operation);
  if (!parsedOperation.ok) return { status: 400, body: parsedOperation };

  const email = await readServerKnownEmailOtpAddress({
    service: input.service,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  if (!email.ok) return { status: email.status, body: email.body };

  const exportPolicy =
    parsedOperation.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
      ? await authorizeEmailOtpExportPolicy(input.opts, {
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
          phase: 'verify',
          userId: input.userId,
          walletId,
          ...(email.orgId ? { orgId: email.orgId } : {}),
          projectId: toOptionalRecordString(input.claims, 'projectId'),
          environmentId: toOptionalRecordString(input.claims, 'environmentId'),
          appSessionVersion: input.appSessionVersion,
          challengeId,
          sourceIp: input.clientIp,
        })
      : null;

  if (exportPolicy && !exportPolicy.ok) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_verify',
        decision: exportPolicy,
        challengeId,
        otpChannel,
        code: exportPolicy.code,
        message: exportPolicy.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
    return {
      status: 403,
      body: { ok: false, code: exportPolicy.code, message: exportPolicy.message },
    };
  }

  const result = await input.service.verifyEmailOtpChallenge({
    userId: input.userId,
    walletId,
    ...(email.orgId ? { orgId: email.orgId } : {}),
    challengeId,
    otpCode,
    otpChannel,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
    operation: parsedOperation.operation,
  });

  if (result.ok) {
    if (exportPolicy) {
      await input.emitWebhook({
        descriptor: emailOtpExportPolicyWebhookEventDescriptor({
          eventType: 'wallet.email_otp.export_approved',
          source: 'signing_session_verify',
          decision: exportPolicy,
          challengeId: result.challengeId,
          otpChannel,
        }),
        claims: input.claims,
        userId: input.userId,
        walletId,
      });
    }
    const enrollment = await input.service.readEmailOtpEnrollment({
      walletId,
      orgId: readEmailOtpOrgIdFromClaims(input.claims),
    });
    if (!enrollment.ok) {
      return { status: emailOtpStatusCode(enrollment.code), body: enrollment };
    }
    return {
      status: 200,
      body: emailOtpLoginVerifyResponseBody({ result, enrollment }),
    };
  }

  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'signing_session_verify',
    code: result.code,
    message: result.message,
    otpChannel,
    operation: parsedOperation.operation,
    lockedUntilMs:
      typeof (result as { lockedUntilMs?: unknown }).lockedUntilMs === 'number'
        ? Number((result as { lockedUntilMs?: unknown }).lockedUntilMs)
        : undefined,
  })) {
    await input.emitWebhook({
      descriptor,
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  if (exportPolicy) {
    await input.emitWebhook({
      descriptor: emailOtpExportPolicyWebhookEventDescriptor({
        eventType: 'wallet.email_otp.export_denied',
        source: 'signing_session_verify',
        decision: emailOtpExportDeniedDecisionFromResult({
          code: result.code,
          message: result.message,
          policySource: exportPolicy.policySource,
          ...(exportPolicy.policyId ? { policyId: exportPolicy.policyId } : {}),
          ...(exportPolicy.approvalId ? { approvalId: exportPolicy.approvalId } : {}),
        }),
        challengeId,
        otpChannel,
        code: result.code,
        message: result.message,
      }),
      claims: input.claims,
      userId: input.userId,
      walletId,
    });
  }

  return { status: emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpUnsealRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  clientIp?: string;
  service: AuthService;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const loginGrantValidation = validateEmailOtpRequiredString(body, 'loginGrant');
  if (!loginGrantValidation.ok) {
    return { status: loginGrantValidation.status, body: loginGrantValidation.body };
  }
  const loginGrant = loginGrantValidation.value;

  const wrappedCiphertextValidation = validateEmailOtpRequiredString(body, 'wrappedCiphertext');
  if (!wrappedCiphertextValidation.ok) {
    return {
      status: wrappedCiphertextValidation.status,
      body: wrappedCiphertextValidation.body,
    };
  }
  const wrappedCiphertext = wrappedCiphertextValidation.value;

  const sessionHash = await hashEmailOtpAppSessionClaims(input.claims);
  const sessionWalletId = getSessionWalletId(input.claims, input.userId);
  const providerUser = resolveEmailOtpProviderUserId({
    claims: input.claims,
    userId: input.userId,
  });
  if (!providerUser.ok) return providerUser.response;
  const grant = await input.service.consumeEmailOtpGrant({
    loginGrant,
    userId: providerUser.providerUserId,
    walletId: sessionWalletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  if (!grant.ok) return { status: emailOtpStatusCode(grant.code), body: grant };

  const result = await input.service.removeEmailOtpServerSeal({
    wrappedCiphertext,
  });
  if (!result.ok) return { status: emailOtpStatusCode(result.code), body: result };

  return {
    status: 200,
    body: {
      ok: true,
      ciphertext: result.ciphertext,
      enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
    },
  };
}

export async function handleEmailOtpSigningSessionUnsealRoute(input: {
  body: unknown;
  claims: Record<string, unknown>;
  userId: string;
  appSessionVersion: string;
  sessionHash: string;
  clientIp?: string;
  service: AuthService;
  emitWebhook: EmitEmailOtpRouteWebhook;
}): Promise<EmailOtpRouteResponse> {
  const bodyValidation = validateEmailOtpJsonObjectBody(input.body);
  if (!bodyValidation.ok) return { status: bodyValidation.status, body: bodyValidation.body };

  const body = bodyValidation.body;
  const walletValidation = validateSigningSessionWalletId({ body, userId: input.userId });
  if (!walletValidation.ok) return walletValidation.response;
  const walletId = walletValidation.walletId;

  const loginGrantValidation = validateEmailOtpRequiredString(body, 'loginGrant');
  if (!loginGrantValidation.ok) {
    return { status: loginGrantValidation.status, body: loginGrantValidation.body };
  }
  const loginGrant = loginGrantValidation.value;

  const wrappedCiphertextValidation = validateEmailOtpRequiredString(body, 'wrappedCiphertext');
  if (!wrappedCiphertextValidation.ok) {
    return {
      status: wrappedCiphertextValidation.status,
      body: wrappedCiphertextValidation.body,
    };
  }
  const wrappedCiphertext = wrappedCiphertextValidation.value;

  const grant = await input.service.consumeEmailOtpGrant({
    loginGrant,
    userId: input.userId,
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    clientIp: input.clientIp,
  });
  if (!grant.ok) return { status: emailOtpStatusCode(grant.code), body: grant };

  const result = await input.service.removeEmailOtpServerSeal({
    wrappedCiphertext,
  });
  if (!result.ok) return { status: emailOtpStatusCode(result.code), body: result };

  const enrollment = await input.service.readEmailOtpEnrollment({
    walletId,
    orgId: readEmailOtpOrgIdFromClaims(input.claims),
  });
  if (
    enrollment.ok &&
    (enrollment.enrollment.walletId !== walletId ||
      enrollment.enrollment.orgId !== readEmailOtpOrgIdFromClaims(input.claims))
  ) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'forbidden',
        message: 'Email OTP enrollment does not match the restored signing session',
      },
    };
  }

  return {
    status: 200,
    body: emailOtpServerSealResponseBody(result, walletId),
  };
}

export async function handleEmailOtpDevCleanupGoogleRegistrationRoute(input: {
  body: unknown;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const body = input.body && typeof input.body === 'object' ? input.body : {};
  const verified = await input.service.verifyGoogleLogin({
    idToken:
      (body as Record<string, unknown>).idToken ?? (body as Record<string, unknown>).id_token,
  });
  if (!verified.ok || !verified.verified || !verified.userId) {
    const code = verified.code || 'not_verified';
    const status =
      code === 'internal'
        ? 500
        : code === 'not_configured' || code === 'unsupported'
          ? 501
          : code === 'invalid_body'
            ? 400
            : 401;
    return {
      status,
      body: { ok: false, code, message: verified.message || 'Google login failed' },
    };
  }

  const result = await input.service.cleanupGoogleEmailOtpDevRegistrationState({
    providerSubject: verified.providerSubject || verified.userId,
    walletId: (body as Record<string, unknown>).walletId,
    orgId:
      (body as Record<string, unknown>).orgId ??
      ((body as Record<string, unknown>).runtimePolicyScope &&
      typeof (body as Record<string, unknown>).runtimePolicyScope === 'object'
        ? ((body as Record<string, unknown>).runtimePolicyScope as Record<string, unknown>).orgId
        : undefined),
  });
  return { status: result.ok ? 200 : emailOtpStatusCode(result.code), body: result };
}

export async function handleEmailOtpDevOtpOutboxRoute(input: {
  challengeId: string;
  walletId?: string;
  claims: Record<string, unknown>;
  userId: string;
  service: AuthService;
}): Promise<EmailOtpRouteResponse> {
  const challengeId = String(input.challengeId || '').trim();
  const sessionWalletId = getSessionWalletId(input.claims, input.userId);
  const walletId = String(input.walletId || sessionWalletId).trim();
  if (walletId !== sessionWalletId) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'wallet_identity_mismatch',
        message: 'walletId must match the current app session wallet',
      },
    };
  }

  let result = await input.service.readEmailOtpOutboxEntry({
    challengeId,
    userId: input.userId,
    walletId,
  });
  const providerSubject = toOptionalRecordString(input.claims, 'providerSubject');
  if (
    !result.ok &&
    result.code === 'not_found' &&
    isGoogleOidcEmailOtpSession(input.claims) &&
    providerSubject
  ) {
    result = await input.service.readEmailOtpOutboxEntry({
      challengeId,
      userId: providerSubject,
      walletId,
    });
  }
  if (!result.ok && result.code === 'not_found' && walletId !== input.userId) {
    // Dev-only outbox reads are wallet-scoped after the app-session wallet check above.
    // Signing-session OTP challenges are stored under the wallet id, while Google SSO
    // app sessions use the provider subject as userId.
    result = await input.service.readEmailOtpOutboxEntry({
      challengeId,
      userId: walletId,
      walletId,
    });
  }
  return {
    status: result.ok
      ? 200
      : result.code === 'internal'
        ? 500
        : result.code === 'not_found'
          ? 404
          : 400,
    body: result.ok
      ? {
          ok: true,
          challengeId: result.challengeId,
          walletId: result.walletId,
          userId: result.userId,
          otpChannel: result.otpChannel,
          emailHint: result.emailHint,
          otpCode: result.otpCode,
          expiresAt: new Date(result.expiresAtMs).toISOString(),
        }
      : result,
  };
}
